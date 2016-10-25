#!/usr/bin/perl
# Feed carbon with snmp counters from hosts from a nagios server.
# TODO: Only tested with windows atm.
# TODO: Add a global snmp timeout to deal with stalled connections.

use strict;
use warnings;
use SNMP;
use IO::Socket::INET;
use LWP::UserAgent;
use HTML::Entities; # decode_entities
use Storable;       # store, retrieve
use Cwd 'abs_path';
use Data::Dumper;
use Time::HiRes qw( gettimeofday );

my %params = ( interval       => 60                          #
             , skip_empty     => 1                           #
             , nagios_url     => "http://nagios.fqdn/nagios" #
             , nagios_user    => "xxxxxxxxx"                 #
             , nagios_pass    => "xxxxxxxxx"                 #
             , nagios_regexp  => "win-\\w+"                  #
             , nagios_hosts   => []                          #
             , snmp_community => 'public'                    #
             , snmp_running   => 0                           #
             , snmp_parallel  => 10                          #
             , carbon_path    => 'collector.windows'         #
             , carbon_server  => 'carbon1'                   #
             , carbon_port    => 2003                        #
             , carbon_proto   => 'tcp'                       #
             , carbon_buffer  => ''                          #
             , debug          => 0                           #
             );

my %oids = ( '.1.3.6.1.2.1.25.3.3.1.2'   => { 'OID' => 'hrProcessorLoad' }
           , '.1.3.6.1.2.1.25.2.3.1.3'   => { 'OID' => 'hrStorageDescr' }
           , '.1.3.6.1.2.1.25.2.3.1.4'   => { 'OID' => 'hrStorageAllocationUnits' }
           , '.1.3.6.1.2.1.25.2.3.1.5'   => { 'OID' => 'hrStorageSize' }
           , '.1.3.6.1.2.1.25.2.3.1.6'   => { 'OID' => 'hrStorageUsed' }
           , '.1.3.6.1.2.1.25.1.6'       => { 'OID' => 'hrSystemProcesses' }
           , '.1.3.6.1.2.1.4.20.1.2'     => { 'OID' => 'ipAdEntIfIndex' }
           , '.1.3.6.1.2.1.2.2.1.10'     => { 'OID' => 'ifEntryInOctets' }
           , '.1.3.6.1.2.1.2.2.1.16'     => { 'OID' => 'ifEntryOutOctets' }
           , '.1.3.6.1.2.1.2.2.1.13'     => { 'OID' => 'ifInDiscards' }
           , '.1.3.6.1.2.1.2.2.1.19'     => { 'OID' => 'ifOutDiscards' }
           , '.1.3.6.1.2.1.2.2.1.14'     => { 'OID' => 'ifInErrors' }
           , '.1.3.6.1.2.1.2.2.1.20'     => { 'OID' => 'ifOutErrors' }
           , '.1.3.6.1.4.1.9827.1.1.1.1' => { 'OID' => 'WFActive' }
           );

my $fullpath = abs_path($0);

#{{{ sub timelog
sub timelog {
    my $text = shift;
    my $now = scalar localtime();
    open(LOG, ">> $fullpath.log") || die "Can't redirect stdout";
    print LOG "$now $text\n";
    close(LOG);
    return print "$now $text\n";
}
#}}}
#{{{ sub fetch_hosts
sub fetch_hosts {
    my $ua = LWP::UserAgent->new(timeout => 5);
    my $req = HTTP::Request->new(GET => "$params{nagios_url}/cgi-bin/config.cgi?type=hosts");
    $req->authorization_basic("$params{nagios_user}", "$params{nagios_pass}");
    my $res = $ua->request($req);
    print $res->headers_as_string."\n" if $params{debug};
    my $page = decode_entities($res->content);
    my %hash = ();
    $hash{lc($1)} = lc($2) while $page =~ />($params{nagios_regexp})<\/TD>\n<TD CLASS='data\w+'>([^<]+)<\/TD>/sg;
    my @array = map { { lc($_) => lc($hash{$_}) } } keys %hash;
    return @array;
}
#}}}
#{{{ sub putval
sub putval {
    my $time = $params{last_run} || timelog("EE Got no time!.");
    my $metric = shift || 0;
    my $value  = shift || 0;
    my $flush  = 0;

    if ($metric) {
        return 0 unless $value and $params{skip_empty};
        $metric = lc($metric);
        $metric =~ s/[^\w\-\._|]+/_/g;
        $metric =~ s/_+/_/g;
        $metric = "$params{carbon_path}.$metric ${value} ${time}";
        timelog("DD $metric") if $params{debug} == 2;
    } elsif ($params{carbon_buffer}) {
        timelog("DD Forcefully flushing buffer to carbon.") if $params{debug} == 2;
        $flush = 1;
    } else {
        timelog("DD Putval called with nothing to do!.") if $params{debug} == 2;
    }

    my $buffsize = length($params{carbon_buffer});
    my $metlen = length($metric);

    if ( $flush or ($buffsize+$metlen) > 1428 ) { # Ethernet - (IPv6 + TCP) = 1500 - (40 + 32) = 1428 bytes
        timelog("DD Sending buffer ($buffsize bytes) to carbon.") if $params{debug} == 2;
        my $sock = IO::Socket::INET->new( PeerAddr => $params{carbon_server}
                                        , PeerPort => $params{carbon_port}
                                        , Proto    => $params{carbon_proto}
                                        );
        timelog("EE Unable to connect to $params{carbon_server}:$params{carbon_port} $params{carbon_proto}, $!.") unless ($sock->connected);
        $sock->send($params{carbon_buffer}) unless $params{debug};
        $params{carbon_buffer} = '';
    }

    $params{carbon_buffer} .= "$metric\n";
}
#}}}
#{{{ sub async_snmp
sub async_snmp {
    my $hostref = shift;
    my ($hostname, $ip) = each %$hostref;
    timelog("DD Adding $hostname ($ip).") if $params{debug};
    my $session = new SNMP::Session( 'DestHost'   => $ip
                                   , 'Community'  => $params{snmp_community}
                                   , 'Version'    => '2c'    # No bulkwalk on v1
#                                   , 'Timeout'    => 3000000 # Microseconds
#                                   , 'Retries'    => 3
                                   , 'UseNumeric' => 1       # Return dotted decimal OID
                                   );

    my @VarBinds =();
    push @VarBinds, new SNMP::Varbind([$_]) foreach keys %oids;
    my $VarList = new SNMP::VarList(@VarBinds);
    $params{snmp_running}++;
    my $reqid = $session->bulkwalk(0, 1, $VarList, [ \&callback, $VarList, $session, $hostname ]);
    timelog("EE Cannot do async bulkwalk: $session->{ErrorStr} ($session->{ErrorNum}).") if $session->{ErrorNum};
}
#}}}
#{{{ sub callback
sub callback {
    my ($VarList, $session, $host, $values) = @_;
    timelog("DD $host entered callback, got $params{snmp_running} threads left.") if $params{debug};
    if ($session->{ErrorNum}) {
        timelog("EE $host Error ".$session->{ErrorNum}." ".$session->{ErrorStr}." on ".$session->{ErrorInd});
    } else {
        my $i=0;
        my %arrays=();
        for my $vbarr (@$values) {
            my $oid = $$VarList[$i++]->tag();
            foreach my $v (@$vbarr) {
                push(@{ $arrays{$oids{$oid}{OID}}{VAL} }, $v->val);
                push(@{ $arrays{$oids{$oid}{OID}}{DIFF} }, substr($v->name, -(length($v->name)-length($oid)-1)));
            }
        }

        my %ifaces;
        @ifaces{@{ $arrays{ipAdEntIfIndex}{VAL} }} = @{ $arrays{ipAdEntIfIndex}{DIFF} };
        foreach my $index (0..$#{$arrays{ifEntryInOctets}{DIFF}}) {
            next unless $ifaces{$arrays{ifEntryInOctets}{DIFF}->[$index]};
            next unless $arrays{ifEntryInOctets}{VAL}->[$index];
            my $nic = "nic".($index+1)."_$ifaces{$arrays{ifEntryInOctets}{DIFF}->[$index]}";
            $nic =~ s/[\.]+/-/g;
            putval("${host}.${nic}_ifEntryInOctets",  $arrays{ifEntryInOctets}{VAL}->[$index]);
            putval("${host}.${nic}_ifEntryOutOctets", $arrays{ifEntryOutOctets}{VAL}->[$index]);
            putval("${host}.${nic}_ifInErrors",       $arrays{ifInErrors}{VAL}->[$index]);
            putval("${host}.${nic}_ifOutErrors",      $arrays{ifOutErrors}{VAL}->[$index]);
            putval("${host}.${nic}_ifInDiscards",     $arrays{ifInDiscards}{VAL}->[$index]);
            putval("${host}.${nic}_ifOutDiscards",    $arrays{ifOutDiscards}{VAL}->[$index]);
        }

        my $cpuall;
        if ($arrays{hrProcessorLoad}{VAL}) {
            my $cpunumber = scalar @{ $arrays{hrProcessorLoad}{VAL} };
            foreach my $cpu (0..$#{$arrays{hrProcessorLoad}{VAL}}) {
                putval("${host}.cpu_${cpu}", $arrays{hrProcessorLoad}{VAL}->[$cpu]);
                $cpuall += $arrays{hrProcessorLoad}{VAL}->[$cpu];
            }
            putval("${host}.cpu_all", $cpuall/$cpunumber);
        }

        foreach my $store (0..$#{$arrays{hrStorageDescr}{VAL}}) {
            my $size = ($arrays{hrStorageSize}{VAL}->[$store]*$arrays{hrStorageAllocationUnits}{VAL}->[$store]);
            my $used = ($arrays{hrStorageUsed}{VAL}->[$store]*$arrays{hrStorageAllocationUnits}{VAL}->[$store]);
            my $percent = 0;
            $percent = (($used*100)/$size) if $size;
            putval("$host.disk_$arrays{hrStorageDescr}{VAL}->[$store]_size",    $size);
            putval("$host.disk_$arrays{hrStorageDescr}{VAL}->[$store]_used",    $used);
            putval("$host.disk_$arrays{hrStorageDescr}{VAL}->[$store]_percent", sprintf("%.2f", $percent));
        }

        putval("$host.system_processes", $arrays{hrSystemProcesses}{VAL}->[0]) if $arrays{hrSystemProcesses}{VAL}->[0];

        putval("$host.citrix_sessions", $arrays{WFActive}{VAL}->[0]) if $arrays{WFActive}{VAL}->[0];
    }

    $params{snmp_running}--;
    timelog("DD $host left callback, got $params{snmp_running} threads left.") if $params{debug};

    if( my $hostref = pop(@{$params{nagios_hosts}}) ) {
        async_snmp($hostref);
    }

    if ($params{snmp_running} <= 0) {
        timelog("DD No threads left, finishing...") if $params{debug};
        return SNMP::finish;
    }
}
#}}}

sub main {
    my $run_count = 0;
    my $fullpath = abs_path($0);

    while (1) {
        ($params{last_run}) = gettimeofday(); # test

        my $next_run = $params{last_run} + $params{interval};
        ${run_count}++;
        timelog("DD Begin ${run_count}th run.") if $params{debug};

        timelog("DD Fetching hosts from '$params{nagios_url}'...") if $params{debug};
        @{$params{nagios_hosts}} = fetch_hosts;
        my $hosts_count = @{$params{nagios_hosts}};

        if ($hosts_count) {
            store(\@{$params{nagios_hosts}}, "$fullpath.hosts") or die "Can't store data!\n";
        } elsif (-f "$fullpath.hosts") {
            timelog("EE Could not fetch hosts, retrieving local data.");
            @{$params{nagios_hosts}} = retrieve("$fullpath.hosts");
        } else {
            timelog("EE Could not fetch hosts, and got no local data!!");
        }

        timelog("II ${run_count}th run for $hosts_count hosts.");

        while ( my $hostref = pop(@{$params{nagios_hosts}})) {
            async_snmp($hostref);
            if ($params{snmp_running} >= $params{snmp_parallel}) {
                timelog("DD reached snmp_parallel ($params{snmp_running}), won't thread more.") if $params{debug};
                last;
            }
        }

        SNMP::MainLoop( ((3/4)*$params{interval}), &SNMP::finish() );

        while ((my $timeleft = ($next_run - time ())) > 0) {
            my $exectime = ($params{interval}-${timeleft});
            putval('execution_time', $exectime);
            putval('host_count', $hosts_count);
            putval();
            timelog("II ${run_count}th run took ${exectime}s, sleeping for ${timeleft}s.");
            sleep ($timeleft)
        }
    }
} # main

main();

# vim: set filetype=perl fdm=marker tabstop=4 shiftwidth=4 nu:
