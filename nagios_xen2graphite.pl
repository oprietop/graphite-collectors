#!/usr/bin/perl
use strict;
use warnings;

use LWP::UserAgent;
use HTTP::Request::Common;
use HTML::Entities; # decode_entities
use Storable;       # store, retrieve
use IO::Socket::INET;
use Cwd 'abs_path';
use Data::Dumper;

my $fullpath = abs_path($0);

my $ua = LWP::UserAgent->new( agent         => 'Mac Safari'
#                            , show_progress => 1 # Adds fancy progressbars
                            , timeout       => 3
                            , ssl_opts      => { verify_hostname => 0 }
                            );

my %params = ( interval       => 60                           #
             , skip_empty     => 1                            #
             , nagios_url     => "http://nagios.fqdn/nagios"  #
             , nagios_user    => "xxxxxxx"                    #
             , nagios_pass    => "xxxxxxx"                    #
             , xenapi_user    => 'xxxxxxx'                    #
             , carbon_path    => 'collector.xen'              #
             , carbon_servers  => [ 'carbon1', 'carbon2' ]    #
             , carbon_port    => 2003                         #
             , carbon_proto   => 'tcp'                        #
             , debug          => 0                            #
             );

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
    my $url = "$params{nagios_url}/cgi-bin/config.cgi?type=services";
    my $page = get_request($url, $params{nagios_user}, $params{nagios_pass});
    my %tmphash = ();
    while ($page =~ /check_xen!([^!]+)!([^!]+)!HOSTS/sg) {
        my ($host, $pass,) = (lc($1), $2);
        $tmphash{$host} = $pass;
    }
    return %tmphash;
}
#}}}
#{{{ sub get_request(@)
sub get_request (@) {
    my ($url, $user, $pass) = @_;
    my ($rcount, $rmax) = (0,3);
    while (1) {
        my $req = HTTP::Request->new(GET => $url);
        $req->authorization_basic($user, $pass);
        my $resp = $ua->request($req);
        $resp->is_success ? return decode_entities($resp->content) : $rcount++;
        timelog("EE Request failed. Retry count: $rcount ($url)");
        return 0 if $rcount >= $rmax;
   }
}
#}}}
#{{{ sub api_call(@)
sub api_call (@) {
    my ($host, $method, @params) = @_;
    my $params_string = '';
    $params_string .= '<param><value><string>'.$_.'</string></value></param>' foreach @params;
    timelog("DD Host: '$host' Method: '$method' Params_string: '$params_string'") if $params{debug};
    my ($rcount, $rmax) = (0,3);
    while (1) {
        my $response = $ua->request( POST "http://$host"
                                   , Content_Type => 'text/xml'
                                   , Content      => '<?xml version="1.0" encoding="us-ascii"?><methodCall><methodName>'.$method.'</methodName><params>'.$params_string.'</params></methodCall>'
                                   );
        if ($response->is_success) {
            my $content = decode_entities($response->decoded_content);
            timelog("DD Response: $content") if $params{debug} > 1;
            return $content;
        } else {
            timelog("EE Request failed($rcount). Host: '$host' Method: '$method' Params_string: '$params_string'");
            timelog('EE '.$response->error_as_HTML);
            $rcount++;
        }
        return 0 if $rcount >= $rmax;
    }
}
#}}}
#{{{ sub check_master(@)
sub check_master(@) {
    my ($host, $or) = @_;
    my $pools = api_call($host, 'pool.get_all_records', $or);
    if (my ($master) =  $pools =~ />HOST_IS_SLAVE<\/value><value>([^<]+)</) {
        timelog("EE '$host' is slave, pool master is '$master'.");
        $pools = api_call($master, 'pool.get_all_records', $or);
        $host = $master;
    }

    my ($poolname) = $pools =~ /<member><name>name_label<\/name><value>([^<]+)<\/value><\/member>/sg;
    timelog("DD Adding POOL: $poolname from HOST: $host ($or).") if $params{debug};

    return ( POOL => $poolname
           , HOST => $host
           , OR   => $or
           );
}
#}}}
#{{{ sub get_vms(@)
sub get_vms(@) {
    my ($host, $or) = @_;
    my $bsd = api_call($host, 'VM.get_all_records', $or);
    my %names = ();
    while ($bsd =~ /<struct><member>(.+?)<\/member><\/struct>/sg) {
        my $struct = $1;
        my %temp = ();
        while ($struct =~ /<name>([^<]+)<\/name><value>(([^<]+))<\/value>/sg) {
           $temp{$1} = $2;
       }
       $names{$temp{uuid}} = $temp{name_label} if ($temp{uuid} and $temp{name_label});
    }
    return %names
}
#}}}
#{{{ sub parse_rrds(@)
sub parse_rrds(@) {
    my ($xml,$names,$pass) = @_;
    my $buffsize = length($xml);
    my ($rows, $columns) = $xml =~ />(\d+)<\/rows><columns>(\d+)</;
    timelog("DD XML is $buffsize bytes, with $rows rows and $columns columns.") if $params{debug};
    my @vs = ();
    push(@vs, $1) while ( $xml =~ /<v>([^<]+)<\/v>/sg );
    my @last_row = @vs[-$columns..-1];

    my %hash = ();
    my $count = 0;
    while ( $xml =~ /<entry>AVERAGE:vm:([^:]+):([^<]+)<\/entry>/sg ) {
        if ($names->{$1} and $names->{$1} !~ /Control domain on host/) {
            $hash{$names->{$1}}{$2} = $last_row[${count}];
            timelog("DD $names->{$1} $2 => $hash{$names->{$1}}{$2}") if $params{debug} > 1;
        }
        ${count}++;
    }
    timelog("DD got $count metrics.") if $params{debug};
    return %hash;
}
#}}}
#{{{ sub carbon_send($)
sub carbon_send($) {
    my $payload = shift;
    my $buffsize = length($payload);
    timelog("DD No buffer to send to carbon.") if $params{debug};
    return 0 unless $buffsize;
    foreach my $carbon_server (@{ $params{carbon_servers} }) {
        timelog("DD Sending buffer ($buffsize bytes) to carbon server '$carbon_server'.") if $params{debug};
        my $sock = IO::Socket::INET->new( PeerAddr => $carbon_server
                                        , PeerPort => $params{carbon_port}
                                        , Proto    => $params{carbon_proto}
                                        );
        timelog("EE Unable to connect to $carbon_server:$params{carbon_port} $params{carbon_proto}, $!.") unless $sock;
        $sock->sockopt(SO_KEEPALIVE, 1);
        $sock->send($payload) unless $params{debug} > 1;
    }
}
#}}}

my $run_count = 0;
while (1) {
    $params{last_run} = time();
    my $next_run = $params{last_run} + $params{interval};
    ${run_count}++;
    timelog("DD Begin ${run_count}th run at epoch '$params{last_run}'.") if $params{debug};
    timelog("DD Fetching hosts from '$params{nagios_url}'...") if $params{debug};

    my %pools = fetch_hosts();
    my $hosts_count = scalar keys %pools;

    if ($hosts_count) {
        timelog("DD Storing hash on disk with $hosts_count hosts.") if $params{debug};
        store(\%pools, "$fullpath.hosts") or die "Can't store data!\n";
    } elsif (-f "$fullpath.hosts") {
        timelog("EE Could not fetch hosts, retrieving local data.");
        my $tmphashref = retrieve("$fullpath.hosts");
        %pools = %{ $tmphashref };
        $hosts_count = scalar keys %pools;
    } else {
        timelog("EE Could not fetch hosts, and got no local data!!");
        die;
    }

    timelog("II ${run_count}th run for $hosts_count hosts.");

    foreach my $dom0 ( keys %pools) {
        timelog("II Trying '$dom0'...") if $params{debug};
        my ($host, $user, $pass) = ($dom0, $params{xenapi_user}, $pools{$dom0});
        my $call = api_call($host, 'session.login_with_password', $user, $pass) or next;
        my ($or) = $call =~ /(OpaqueRef:[^<]+)</;
        my %good = check_master($host, $or);
        my $pool = lc($good{POOL});
        my %names = get_vms($good{HOST}, $good{OR});
        my $pool_hosts = api_call($good{HOST}, 'host.get_all', $good{OR});
        while ($pool_hosts =~ /(OpaqueRef:[^<]+)</sg) {
            my $host_ip = api_call($good{HOST}, 'host.get_address', $good{OR}, $1);
            my ($ip) = $host_ip =~ /<name>Status<\/name><value>Success<\/value><\/member><member><name>Value<\/name><value>([^<]+)<\/value>/;
            my $epoch = ($params{last_run} - 660); # Try to get the 1min metrics
            my $xml = get_request("http://$ip/rrd_updates?session_id=$good{OR}&start=$epoch&interval=60"); # With interval 60 we force 1 minute rows
            my %metrics =  parse_rrds($xml, \%names);
            my $vms  = scalar keys %metrics;
            timelog("II [$pool] Got $vms VMs from '$ip'.");
            my $payload = '';
            foreach my $vm (keys %metrics) {
                while (my ($mkey, $mvalue) = each %{ $metrics{$vm} }) {
                    if ($mvalue and $params{skip_empty}) {;
                        my $metric = "$params{carbon_path}.$pool.$vm.$mkey $mvalue $params{last_run}";
                        timelog ("DD $metric") if $params{debug} > 1;
                        $payload .= "$metric\n";
                    }
                }
            }
            carbon_send($payload);
        }
    }

    while ((my $timeleft = ($next_run - time())) > 0) {
        my $exectime = ($params{interval}-${timeleft});
        timelog("II ${run_count}th run took ${exectime}s, sleeping for ${timeleft}s.");
        my $payload = "$params{carbon_path}.execution_time $exectime $params{last_run}\n";
        $payload .= "$params{carbon_path}.host_count_time $hosts_count $params{last_run}\n";
        carbon_send($payload);
        sleep ($timeleft);
    }
}

exit 0;
# vim: set filetype=perl fdm=marker tabstop=4 shiftwidth=4 nu:
