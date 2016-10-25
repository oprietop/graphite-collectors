#!/usr/bin/perl
# Feed carbon with windows snmp dhcp counters

use strict;
use warnings;
use Socket;
use SNMP;
use Parallel::ForkManager;
use IO::Socket::INET;
use Cwd 'abs_path';

# All the configuration variables will be populated here.
my %params = ( interval       => 60                       #
             , skip_empty     => 1                        #
             , domain         => 'domain.fwdn'            #
             , snmp_community => 'public'                 #
             , snmp_parallel  => 32                       #
             , carbon_path    => 'collector.dhcp_leases'  #
             , carbon_servers => [ 'carbon1', 'carbon2' ] #
             , carbon_port    => 2003                     #
             , carbon_proto   => 'tcp'                    #
             , full_path      => abs_path($0)             #
             , debug          => 0                        #
             );

# Hash of Hashes with our usefull OIDs.
my %oids = ( '.1.3.6.1.4.1.311.1.3.1.2'      => { 'OID'  => 'parDhcpTotalNoOfDiscovers' }
           , '.1.3.6.1.4.1.311.1.3.1.3'      => { 'OID'  => 'parDhcpTotalNoOfRequests' }
           , '.1.3.6.1.4.1.311.1.3.1.4'      => { 'OID'  => 'parDhcpTotalNoOfReleases' }
           , '.1.3.6.1.4.1.311.1.3.1.5'      => { 'OID'  => 'parDhcpTotalNoOfOffers' }
           , '.1.3.6.1.4.1.311.1.3.1.6'      => { 'OID'  => 'parDhcpTotalNoOfAcks' }
           , '.1.3.6.1.4.1.311.1.3.1.7'      => { 'OID'  => 'parDhcpTotalNoOfNacks' }
           , '.1.3.6.1.4.1.311.1.3.1.8'      => { 'OID'  => 'parDhcpTotalNoOfDeclines' }
           , '.1.3.6.1.4.1.311.1.3.2.1.1.1'  => { 'OID'  => 'subnetAdd' }
           , '.1.3.6.1.4.1.311.1.3.2.1.1.2'  => { 'OID'  => 'noAddInUse' }
           , '.1.3.6.1.4.1.311.1.3.2.1.1.3'  => { 'OID'  => 'noAddFree' }
           , '.1.3.6.1.4.1.311.1.3.2.1.1.4'  => { 'OID'  => 'noPendingOffers' }
           , '.1.3.6.1.2.1.1.5'              => { 'OID'  => 'sysName' }
           );

# This hash will work as a dispatcher to easily pass around our functions/callbacks allowing us to work in a state machine fashion.
my %functions = ( timelog        => \&timelog
                , carbon_send    => \&carbon_send
                , prepare_metric => \&prepare_metric
                , snmp_parse     => \&snmp_parse
                , snmp_timeout   => \&snmp_timeout
                , snmp_result    => \&snmp_result
                , snmp_callback  => \&snmp_callback
                , snmp_async     => \&snmp_async
                , main           => \&main
                , whoami         => sub { ( caller(1) )[3] } # Returns the current function name
                , whowasi        => sub { ( caller(2) )[3] } # Returns the current function caller
                );


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

    $hostref->{FULL} = $hostref->{SNMP_RESULTS}{sysName}{VAL}[0];
    $hostref->{FULL} =~ s/\..+//g;
    return unless $hostref->{FULL};

    # Scope stats
    foreach my $i (0..$#{ $hostref->{SNMP_RESULTS}{subnetAdd}{VAL} }) {
        my $scope = $hostref->{SNMP_RESULTS}{subnetAdd}{VAL}[$i];
        $scope =~ s/\./\-/g;
        foreach my $oid ( qw/noAddInUse noAddFree noPendingOffers/ ) {
            next unless $hostref->{SNMP_RESULTS}{noAddInUse}{VAL}[$i];
            $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.$hostref->{FULL}.leases.$scope.$oid", $hostref->{SNMP_RESULTS}{$oid}{VAL}[$i]);
        }
    }

    # Server Stats
    foreach my $oid ( qw/parDhcpTotalNoOfDiscovers parDhcpTotalNoOfRequests parDhcpTotalNoOfReleases parDhcpTotalNoOfOffers parDhcpTotalNoOfAcks parDhcpTotalNoOfNacks parDhcpTotalNoOfDeclines/) {
        $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.$hostref->{FULL}.counters.$oid", $hostref->{SNMP_RESULTS}{$oid}{VAL}[0]);
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
            my $value = $v->val;
            push(@{ $hostref->{SNMP_RESULTS}{$oids{$oid}{OID}}{VAL} }, $value);
        }
    }
    $functions{snmp_parse}->($hostref);
}
 #}}}
#{{{ sub snmp_async
sub snmp_async {
    my $hostref = shift;
    $hostref->{SNMP_BEGIN} = int (time() * 1000);

    # Initialize a SNMP::Session and fetch oor OIDs
    $hostref->{SESSION} = new SNMP::Session( 'DestHost'   => $hostref->{IP}
                                           , 'Community'  => $params{snmp_community}
                                           , 'Version'    => '2c'    # No bulkwalk on v1
                                           , 'UseNumeric' => 1       # Return dotted decimal OID
                                           );
    $functions{timelog}->("EE Cannot do async bulkwalk: $hostref->{SESSION}->{ErrorStr} ($hostref->{SESSION}->{ErrorNum}).") if $hostref->{SESSION}->{ErrorNum};

    my @VarBinds =();
    push @VarBinds, new SNMP::Varbind([$_]) foreach keys %oids;
    $hostref->{VARLIST} = new SNMP::VarList(@VarBinds);

    @{ $hostref->{BULKWALK} } = $hostref->{SESSION}->bulkwalk(0, 1, $hostref->{VARLIST});

    if ($hostref->{SESSION}->{ErrorNum}) {
        $functions{timelog}->("EE ($hostref->{IP}) Error ".$hostref->{SESSION}->{ErrorNum}." ".$hostref->{SESSION}->{ErrorStr}." on ".$hostref->{SESSION}->{ErrorInd});
    }

    # Useful info to send to carbon, even if snmp failed.
    $hostref->{SNMP_END}     = int (time() * 1000);
    $hostref->{SNMP_TIME}    = $hostref->{SNMP_END} - $hostref->{SNMP_BEGIN};
    $hostref->{SNMP_SECONDS} = ($hostref->{SNMP_TIME}/1000);
    $hostref->{SNMP_KEYS} = scalar @{ $hostref->{BULKWALK} };
    $functions{timelog}->("DD ($hostref->{IP}) got $hostref->{SNMP_KEYS} keys on $hostref->{SNMP_SECONDS} seconds.") if $params{debug} > 1;

    $hostref = $functions{snmp_result}->($hostref);
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

        my @addresses = gethostbyname($params{domain}) or die "Can't resolve $params{domain}: $!\n";
        @addresses = map { inet_ntoa($_) } @addresses[4 .. $#addresses];
        map { $params{nagios_results}{$_} = { IP => $_ } } @addresses;

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
            my $pid = $pm->start($hostref->{IP}) and next;
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
