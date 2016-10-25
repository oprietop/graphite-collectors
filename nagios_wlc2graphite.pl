#!/usr/bin/perl
# Feed carbon with ssid related snmp counters from a cisco wlc

use strict;
use warnings;
use SNMP;
use IO::Socket::INET;
use Cwd 'abs_path';

# All the configuration variables will be populated here.
my %params = ( interval       => 60                                    #
             , skip_empty     => 1                                     #
             , wlc_host       => "wlc.hostname"                        #
             , snmp_community => 'public'                              #
             , carbon_path    => 'torrente.wlc'                        #
             , carbon_servers => [ 'carbon1', 'carbon2' ]              #
             , carbon_port    => 2003                                  #
             , carbon_proto   => 'tcp'                                 #
             , full_path      => abs_path($0)                          #
             , debug          => 0                                     #
             );

# Hash of Hashes with our useful OIDs.
my %oids = ( '1.3.6.1.4.1.14179.2.2.1.1.1'  => { 'OID'  => 'APMacAddress'
                                               , 'TYPE' => 'hex'
                                               }
           , '1.3.6.1.4.1.14179.2.2.1.1.3'  => { 'OID'  => 'APName' }
           , '1.3.6.1.4.1.14179.2.1.4.1.4'  => { 'OID'  => 'UserAPMacAddr'
                                               , 'TYPE' => 'hex'
                                               }
           , '1.3.6.1.4.1.14179.2.1.4.1.7'  => { 'OID'  => 'UserSsid' }
           );

# This hash will work as a dispatcher to easily pass around our functions/callbacks allowing us to work in a state machine fashion.
my %functions = ( timelog        => \&timelog
                , carbon_send    => \&carbon_send
                , prepare_metric => \&prepare_metric
                , snmp_parse     => \&snmp_parse
                , snmp_timeout   => \&snmp_timeout
                , snmp_result    => \&snmp_result
                , snmp_walk      => \&snmp_walk
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
    my $hostref = shift;
    # Create a hash of arrays with the snmp results
    my $i=0;
    my %new_data = ();
    for my $vbarr (@{ $hostref->{BULKWALK} }) {
        my $oid = ${ $hostref->{VARLIST} }[$i++]->tag();
        foreach my $v (@$vbarr) {
            my $value = $v->val;
            if ($oids{$oid}{TYPE} and $oids{$oid}{TYPE} eq 'hex') {
                $value = unpack('H*', $v->val);
                $value = join(':', unpack '(A2)*', uc($value));
            }
            push(@{ $new_data{$oids{$oid}{OID}}{VAL} }, $value);
        }
    }

    # Join the AP mac addresses and Names array into a hash
    my %aps;
    @aps{@{ $new_data{APMacAddress}{VAL} }} = @{ $new_data{APName}{VAL} };

    # Traverse our hash of arrays pupulating the results hash
    foreach my $i (0..$#{ $new_data{UserAPMacAddr}{VAL} }) {
        my $ap   = $aps{$new_data{UserAPMacAddr}{VAL}[$i]};
        my $ssid = $new_data{UserSsid}{VAL}[$i];
        $hostref->{RESULT}->{$ap}->{$ssid}++;
    }

    # Traverse our results hash and build our metrics
    foreach my $ap ( sort keys %{ $hostref->{RESULT} } ) {
        foreach my $ssid ( sort keys %{ $hostref->{RESULT}->{$ap} } ) {
 #           print "$ap -> $ssid -> $hostref->{RESULT}->{$ap}->{$ssid}\n";
            $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.aps.$ap.$ssid", $hostref->{RESULT}->{$ap}->{$ssid});
        }
    }

    $hostref->{PAYLOAD_SIZE} = length($hostref->{PAYLOAD});
    $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.stats.payload_size", $hostref->{PAYLOAD_SIZE});
    $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.stats.keys", $hostref->{SNMP_KEYS});
    $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.stats.smtp_time", $hostref->{SNMP_TIME});

    $functions{timelog}->("II GOT a paylod of hostref->{PAYLOAD_SIZE} bytes to send to carbon") if $params{debug};
    $functions{carbon_send}->($hostref);
}
#}}}
#{{{ sub snmp_walk
sub snmp_walk {
    my $hostref = shift;
    $hostref->{SNMP_BEGIN} = int (time() * 1000);

    # Initialize a SNMP::Session and fetch oor OIDs
    $hostref->{SESSION} = new SNMP::Session( 'DestHost'   => $params{wlc_host}
                                           , 'Community'  => $params{community}
                                           , 'Version'    => '2c' # No bulkwalk on v1
                                           , 'UseNumeric' => 1   # Return dotted decimal OID
                                           );
    $functions{timelog}->("EE Cannot do bulkwalk: $hostref->{SESSION}->{ErrorStr} ($hostref->{SESSION}->{ErrorNum}).") if $hostref->{SESSION}->{ErrorNum};

    my @VarBinds =();
    push @VarBinds, new SNMP::Varbind([$_]) foreach keys %oids;
    $hostref->{VARLIST} = new SNMP::VarList(@VarBinds);
    @{ $hostref->{BULKWALK} } = $hostref->{SESSION}->bulkwalk(0, 1, $hostref->{VARLIST});

    if ($hostref->{SESSION}->{ErrorNum}) {
        $functions{timelog}->("EE $hostref->{NAME} ($hostref->{IP}) Error ".$hostref->{SESSION}->{ErrorNum}." ".$hostref->{SESSION}->{ErrorStr}." on ".$hostref->{SESSION}->{ErrorInd});
        $hostref->{PAYLOAD} .= $functions{prepare_metric}->("$params{carbon_path}.stats.error", 1);
    }

    # Useful info to send to carbon, even if snmp failed.
    $hostref->{SNMP_END}     = int (time() * 1000);
    $hostref->{SNMP_TIME}    = $hostref->{SNMP_END} - $hostref->{SNMP_BEGIN};
    $hostref->{SNMP_SECONDS} = ($hostref->{SNMP_TIME}/1000);
    $hostref->{SNMP_KEYS} = scalar @{ $hostref->{BULKWALK} };
    $functions{timelog}->("DD got $hostref->{SNMP_KEYS} keys on $hostref->{SNMP_SECONDS} seconds.") if $params{debug} > 1;

    $functions{snmp_parse}->($hostref);
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

        # Do Stuff
        $functions{snmp_walk}->();

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
