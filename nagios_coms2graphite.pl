#!/usr/bin/perl
# Feed carbon with snmp counters from hosts from a nagios server.

use strict;
use warnings;
use SNMP;
use Parallel::ForkManager;
use IO::Socket::INET;
use LWP::UserAgent;
use HTML::Entities; # decode_entities
use Cwd 'abs_path';

# All the configuration variables will be populated here.
my %params = ( interval       => 60                          #
             , skip_empty     => 1                           #
             , nagios_url     => "http://nagios.fqdn/nagios" #
             , nagios_user    => "xxxxx"                     #
             , nagios_pass    => "xxxxx"                     #
             , nagios_note    => '\[comms\]'                 #
             , snmp_community => 'public'                    #
             , snmp_parallel  => 32                          #
             , carbon_path    => 'collector.coms'            #
             , carbon_servers => [ 'carbon1', 'carbon2' ]    #
             , carbon_port    => 2003                        #
             , carbon_proto   => 'tcp'                       #
             , full_path      => abs_path($0)                #
             , debug          => 0                           #
             );

# Hash of Hashes with our usefull OIDs.
my %hoh = ( 'interfaces' => { 'NODE1' => { 'name'       => '.1.3.6.1.2.1.31.1.1.1.1'  } # ifXName
                            , 'NODE2' => { 'alias'      => '.1.3.6.1.2.1.31.1.1.1.18' } # ifAlias
                            , 'ITEMS' => { 'bytes_in'   => '.1.3.6.1.2.1.31.1.1.1.6'    # ifHCInOctets
                                         , 'bytes_out'  => '.1.3.6.1.2.1.31.1.1.1.10'   # ifHCOutOctets
                                         , 'ucast_in'   => '.1.3.6.1.2.1.31.1.1.1.7'    # ifHCInUcastPkts
                                         , 'ucast_out'  => '.1.3.6.1.2.1.31.1.1.1.11'   # ifHCOutUcastPkts
                                         , 'mcast_in'   => '.1.3.6.1.2.1.31.1.1.1.8'    # ifHCInMulticastPkts
                                         , 'mcast_out'  => '.1.3.6.1.2.1.31.1.1.1.12'   # ifHCOutMulticastPkts
                                         , 'bcast_in'   => '.1.3.6.1.2.1.31.1.1.1.9'    # ifHCInBroadcastPkts
                                         , 'bcast_out'  => '.1.3.6.1.2.1.31.1.1.1.13'   # ifHCOutBroadcastPkts
                                         , 'drops_in'   => '.1.3.6.1.2.1.2.2.1.13'      # ifInDiscards
                                         , 'drops_out'  => '.1.3.6.1.2.1.2.2.1.19'      # ifOutDiscards
                                         , 'errors_in'  => '.1.3.6.1.2.1.2.2.1.14'      # ifInErrors
                                         , 'errors_out' => '.1.3.6.1.2.1.2.2.1.20'      # ifOutErrors
                                         }

                            }
          , cpu => { 'ITEMS' => { 'huawei'    => '.1.3.6.1.4.1.2011.6.3.4.1.3'          # hwAvgDuty1min
                                , 'junos_re1' => '.1.3.6.1.4.1.2636.3.1.13.1.8.9.1'     # jnxOperatingCPURE1
                                , 'junos_re2' => '.1.3.6.1.4.1.2636.3.1.13.1.8.9.2'     # jnxOperatingCPURE2
                                , 'cisco'     => '.1.3.6.1.4.1.9.9.109.1.1.1.1.8'       # cpmCPUTotal5minRev
                                , 'netscreen' => '.1.3.6.1.4.1.3224.16.1.2'             # nsResCpuLast1Min (x10)
                                , 'enterasys' => '.1.3.6.1.4.1.5624.1.2.49.1.1.1.1.4.1' # etsysResourceCpuLoad5min
                                , 'fujitsu'   => '.1.3.6.1.4.1.231.1.1.3.16'            # agentCpuLoad
                                , 'ipso'      => '.1.3.6.1.4.1.94.1.21.1.7.1'           # ipsoProcessorUtilization
                                , 'vsp'       => '.1.3.6.1.4.1.2272.1.85.10.1.1.2'      # cpuLast1Minute
                                , 'ers'       => '.1.3.6.1.4.1.45.1.6.3.8.1.1.5.3'      # rcKhiSlotCpuCurrentUtil (Table)
                                , 'a10'       => '.1.3.6.1.4.1.22610.2.4.1.3.3'         # axSysAverageCpuUsage
                                , 'palo_alto' => '.1.3.6.1.2.1.25.3.3.1.2'              # hrProcessorLoad
                                }
                   }
          , mem => { 'ITEMS' => { 'huawei'    => '.1.3.6.1.4.1.2011.6.3.4.1.3'          # hwAvgDuty1min
                                , 'vsp'       => '.1.3.6.1.4.1.2272.1.85.10.1.1.8'      # rcKhiSlotMemUtil
                                , 'ers_total' => '.1.3.6.1.4.1.45.1.6.3.8.1.1.12.3'     # memTotal
                                , 'ers_avail' => '.1.3.6.1.4.1.45.1.6.3.8.1.1.13.3'     # memAvailable
                                }
                   }

          , 'uptime' => { 'ITEMS' => { 'uptime'  => '.1.3.6.1.2.1.1.3.0' } } # sysUpTimeInstance (single)
          );

# This hash will work as a dispatcher to easily pass around our functions/callbacks allowing us to work in a state machine fashion.
my %functions = ( hoh_walk       => \&hoh_walk
                , timelog        => \&timelog
                , carbon_send    => \&carbon_send
                , prepare_metric => \&prepare_metric
                , snmp_parse     => \&snmp_parse
                , snmp_timeout   => \&snmp_timeout
                , snmp_result    => \&snmp_result
                , snmp_callback  => \&snmp_callback
                , snmp_async     => \&snmp_async
                , fetch_hosts    => \&fetch_hosts
                , main           => \&main
                , whoami         => sub { ( caller(1) )[3] } # Returns the current function name
                , whowasi        => sub { ( caller(2) )[3] } # Returns the current function caller
                );


#{{{ sub hoh_walk
sub hoh_walk {
    # Traverse a hash of hashes.
    my ($hash, $key_list, $callback) = @_;
    while (my ($key, $value) = each %$hash) {
        push(@$key_list, $key);
        ref($value) eq 'HASH' ? hoh_walk($value, $key_list, $callback) : $callback->($key, $value, $key_list);
        pop @$key_list;
    }
}
#}}}
#{{{ sub timelog
sub timelog {
    # Logging helper function.
    my $text = shift;
    my $now = scalar localtime();
    my $caller = $functions{whowasi}->();
    my $line = "$now [$caller] $text\n";
    open(LOG, ">> $params{full_path}.log") || die "Can't redirect stdout";
    print LOG $line;
    print $line;
    close(LOG);
}
#}}}
#{{{ sub carbon_send
sub carbon_send {
    # Send metrics to carbon servers.
    my $hostref = shift;
    my $payload = $hostref;
    $payload = $hostref->{PAYLOAD} if (ref($hostref) eq "HASH" and $hostref->{PAYLOAD});
    $functions{timelog}->("DD __PAYLOAD__\n${payload}__PAYLOAD__") if $params{debug} > 2;
    foreach my $carbon_server (@{ $params{carbon_servers} }) {
        # We will try 3 times.
        foreach ( 1..3 ) {
            $functions{timelog}->("II Sending payload to $carbon_server:$params{carbon_port} $params{carbon_proto}, Attemp: $_") if $params{debug};
            my $sock = IO::Socket::INET->new( PeerAddr => $carbon_server
                                            , PeerPort => $params{carbon_port}
                                            , Proto    => $params{carbon_proto}
                                            , Timeout  => 3
                                            );
            $functions{timelog}->("EE Unable to connect to $carbon_server:$params{carbon_port} $params{carbon_proto}, $!.") unless $sock;
            next unless $sock;
            # leave the loop if everything went fine.
            next if $params{debug};
            last if $sock->send($payload) or $functions{timelog}->("EE [carbon_send] Error sending: $!");
        }
    }
    return 0;
}
#}}}
#{{{ sub prepare_metric
sub prepare_metric {
    # Clean metrics into compliant carbon ones.
    my $metric = shift || return;
    my $value  = shift || 0;
    $metric = lc($metric);
    $metric =~ s/[^a-z0-9\-\._|]+/_/g;
    $metric =~ s/_+/_/g;
    my $result = "$metric ".int($value).' '.int($params{last_run});
    $functions{timelog}->("DD $result") if $params{debug} >1;
    return "$result\n";
}
#}}}
#{{{ sub snmp_parse
sub snmp_parse {
    # Traverse the data data structure amb build carbon metrics.
    my $hostref = shift;
    foreach my $category (keys %{ $hostref->{SNMP_RESULTS} }) {
        my @nodes = ();
        $functions{hoh_walk}->( \%hoh
                              , []
                              , sub { my ($key, $value, $key_list) = @_;
                                      my ($cat, $type) = @{ $key_list };
                                      return unless $category eq $cat;
                                      if ($type =~ /NODE/) {
                                          push(@nodes, $type);
                                          $functions{timelog}->("DD Got node '$type' inside of '$category'.") if $params{debug} > 1;
                                      }
                                    }
                              );
        foreach my $item ( keys %{ $hostref->{SNMP_RESULTS}->{$category}->{ITEMS} }) {
            my @prefixes = ();
            foreach my $node (sort @nodes) {
                my ($pref) = values %{ $hostref->{SNMP_RESULTS}->{$category}->{$node}->{$item} };
                $pref = 'none' unless $pref;
                push(@prefixes, $pref);
            }
            my $prefix = $category;
            $prefix .= '.'.join('.', @prefixes) if @prefixes;
            $item and $prefix .= ".$item" unless @prefixes;

            while (my ($oid, $value) = each %{ $hostref->{SNMP_RESULTS}->{$category}->{ITEMS}->{$item} }) {
                 $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.$hostref->{FULL}.$prefix.$oid", $value);
            }
        }
    }

    $hostref->{PAYLOAD_SIZE} = length($hostref->{PAYLOAD});
    $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.$hostref->{FULL}.stats.payload_size", $hostref->{PAYLOAD_SIZE});
    $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.$hostref->{FULL}.stats.keys", $hostref->{SNMP_KEYS});
    $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.$hostref->{FULL}.stats.smtp_time", $hostref->{SNMP_TIME});
    return $hostref;
}
#}}}
#{{{ sub snmp_result
sub snmp_result {
    # Parse the snmp results into a complex data sctucture we can work with
    my $hostref = shift;
    my $i=0;
    for my $vbarr (@{ $hostref->{BULKWALK} }) {
        my $oid = ${ $hostref->{VARLIST} }[$i++]->tag();
        foreach my $v (@$vbarr) {
            my $val  = $v->val;
            my $diff = substr($v->name, -(length($v->name)-length($oid)-1));
            $functions{hoh_walk}->( \%hoh
                                  , []
                                  , sub { my ($key, $value, $key_list) = @_;
                                          return if ( $v->name !~ m{^\Q$value\E\.(.+)$} );
                                          my ($category, $type) = @{ $key_list };
                                          if ($type =~ /^R/) { # This will allow to handle ipAdEntIfIndex and other stuff
                                              my ($a, $b) = ($diff, $val);
                                              ($diff, $val) = ($b, $a);
                                          }
                                          $val or return if $params{skip_empty};
                                          $val =~ s/[\.]+/-/g; # Having dots in our results will definitelly mess our graphite AST paths
                                          $functions{timelog}->( sprintf( "%s | %s [%s] = '%s' (%s.%s)"
                                                                        , $oid
                                                                        , $v->name
                                                                        , $diff
                                                                        , $val
                                                                        , $category
                                                                        , $type
                                                                        )
                                                               ) if $params{debug} > 2;
                                          $hostref->{SNMP_RESULTS}->{$category}->{$type}->{$diff}->{$key} = $val;
                                        }
                                  );
        }
    }
    $functions{snmp_parse}->($hostref);
}
#}}}
#{{{ sub snmp_async
sub snmp_async {
    my $hostref = shift;
    $hostref->{FULL} = lc("$hostref->{PREFIX}\.$hostref->{NAME}");
    $hostref->{SNMP_BEGIN} = int (time() * 1000);

    # Initialize a SNMP::Session and fetch oor OIDs
    $hostref->{SESSION} = new SNMP::Session( 'DestHost'   => $hostref->{IP}
                                           , 'Community'  => $hostref->{COMMUNITY}
                                           , 'Version'    => '2c'    # No bulkwalk on v1
#                                           , 'Timeout'    => 3000000 # Microseconds
#                                           , 'Retries'    => 3
                                           , 'UseNumeric' => 1       # Return dotted decimal OID
                                           );
    $functions{timelog}->("EE Cannot do async bulkwalk: $hostref->{SESSION}->{ErrorStr} ($hostref->{SESSION}->{ErrorNum}).") if $hostref->{SESSION}->{ErrorNum};

    my @oids =();
    $functions{hoh_walk}->( \%hoh, [], sub { my ($key, $value) = @_; push(@oids, $value) } );
    my @VarBinds =();
    push @VarBinds, new SNMP::Varbind([$_]) foreach sort @oids;
    $hostref->{VARLIST} = new SNMP::VarList(@VarBinds);

     @{ $hostref->{BULKWALK} } = $hostref->{SESSION}->bulkwalk(0, 1, $hostref->{VARLIST});

    if ($hostref->{SESSION}->{ErrorNum}) {
        $functions{timelog}->("EE $hostref->{NAME} ($hostref->{IP}) Error ".$hostref->{SESSION}->{ErrorNum}." ".$hostref->{SESSION}->{ErrorStr}." on ".$hostref->{SESSION}->{ErrorInd});
        $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.$hostref->{FULL}.stats.error", 1);
    }

    # Useful info to send to carbon, even if snmp failed.
    $hostref->{SNMP_END}     = int (time() * 1000);
    $hostref->{SNMP_TIME}    = $hostref->{SNMP_END} - $hostref->{SNMP_BEGIN};
    $hostref->{SNMP_SECONDS} = ($hostref->{SNMP_TIME}/1000);
    $hostref->{SNMP_KEYS} = scalar @{ $hostref->{BULKWALK} };
    $functions{timelog}->("DD $hostref->{NAME} ($hostref->{IP}) got $hostref->{SNMP_KEYS} keys on $hostref->{SNMP_SECONDS} seconds.") if $params{debug} > 1;

    $hostref = $functions{snmp_result}->($hostref);
}
#}}}
#{{{ sub fetch_hosts
sub fetch_hosts {
    # Fetch the hosts from the nagios config cgi
    my $ua = LWP::UserAgent->new(timeout => 5);
    my $req = HTTP::Request->new( GET => "$params{nagios_url}/cgi-bin/config.cgi?type=services");
    $req->authorization_basic("$params{nagios_user}", "$params{nagios_pass}");
    my $res = $ua->request($req);
    my $header = $res->headers_as_string if $params{debug};
    my $body = decode_entities($res->content);

    # Traverse and parse the page
    $params{nagios_results} = undef;
    while ($body =~ /<TR(.+?)TR>/sg) {
        my $tr = lc($1);
        next unless $tr =~ qr/$params{nagios_note}(.*?)</;
        my $paramlist = $1;
        my $community = $params{snmp_community};
        $community = $1 if $paramlist =~ /community\(([\@\w]+)\)/;
        my $prefix = 'none';
        $prefix = $1 if $paramlist =~ /prefix\(([\w_-]+)\)/;
        if ($tr =~ /<td class='\w+'><a name='([^;]+);([^']+)'.+?chk_([\w_]+)_[^!]+!([\w\.\-_]+)/sg) {
            my ($prefix, $name, $ip) = ("$1.$3", $2, $4);
            $prefix =~ s/^hc-//;
            $name =~ s/^hc-//;
            $params{nagios_results}{$ip} = { IP        => $ip
                                           , NAME      => $name
                                           , PREFIX    => $prefix
                                           , COMMUNITY => $community
                                           };
        }
    }

    my $host_count = scalar values %{ $params{nagios_results} };

    # Keep our results as a backup measure to continue gathering metrics even if nagios fails
    if ($host_count) {
        $functions{timelog}->("II GOT $host_count devices on $params{nagios_url}.");
        $params{nagios_cache} = $params{nagios_results};
    } elsif ($params{nagios_cache}) {
        $host_count = scalar values %{ $params{nagios_cache} };
        $params{nagios_results} = $params{nagios_cache};
        $functions{timelog}->("WW No results from $params{nagios_url}, using the $host_count cached devices.");
    } else {
        $functions{timelog}->("EE No results from $params{nagios_url} and empty cache, waiting...");
        return 1;
    }
}
#}}}

sub main {
    my $run_count = 0;
    # Poor man's timed loop
    while (1) {
        $params{last_run} = time();
        $params{payload} = "";
        my $next_run = int($params{last_run}) + $params{interval};
        ${run_count}++;
        $functions{timelog}->("II Begin ${run_count}th run @ $next_run.");

        $functions{fetch_hosts}->();

        # Single threading SNMP isn't reliable with our desired host count, we'll use P::F
        my $pm = Parallel::ForkManager->new($params{snmp_parallel});

        # P::F Hooks
        $pm->run_on_finish( sub { my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $hostref) = @_;
                                  $functions{timelog}->("II -- $ident($pid) finished on $hostref->{SNMP_SECONDS} seconds.") if $params{debug};
                                  $params{payload} .= $hostref->{PAYLOAD};
                                }
                          );
        $pm->run_on_start( sub { my ($pid, $ident)=@_;
                                 $functions{timelog}->("II ++ $ident($pid) started") if $params{debug};
                               }
                         );
        $pm->run_on_wait( sub { $functions{timelog}->("II ** Waiting for children...") if $params{debug}; }
                        , 1
                        );
        # Fork for each host.
        foreach my $hostref (values %{ $params{nagios_results} }) {
            my $pid = $pm->start($hostref->{NAME}) and next;
            $hostref = $functions{snmp_async}->($hostref);
            $pm->finish(0, $hostref); # Children passes the hostref to the parent.
        }

        # Block Execution until work is done.
        $pm->wait_all_children;

        $functions{timelog}->("II No children left!") if $params{debug};
        $params{payload_size} = length($params{payload});
        $functions{timelog}->("II GOT a paylod of $params{payload_size} bytes to send to carbon") if $params{debug};
        $functions{carbon_send}->($params{payload});

        # Wait until the next loop if we got time left.
        while ((my $timeleft = ($next_run - time())) > 0) {
            my $exectime = ($params{interval}-${timeleft});
            $functions{timelog}->("II ${run_count}th run took ${exectime}s, sleeping for ${timeleft}s.");
            sleep ($timeleft)
        }
    }
} # main

main();

# vim: set filetype=perl fdm=marker tabstop=4 shiftwidth=4 nu:
