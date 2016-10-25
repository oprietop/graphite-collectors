#!/usr/bin/perl

use strict;
use warnings;

use AnyEvent::Strict;
use AnyEvent::HTTP;
use AnyEvent::Log;
use MIME::Base64;
use Data::Dumper;
use Cwd 'abs_path';

my $fullpath = abs_path($0);
$AnyEvent::Log::FILTER->level("note");
#$AnyEvent::Log::LOG->log_to_file("$fullpath.log");
#$AnyEvent::Log::FILTER->level("info");

my $startime;

my %params = ( interval       => 60                          #
             , skip_empty     => 1                           #
             , nagios_url     => "http://nagios.fqdn/nagios" #
             , nagios_user    => "xxxxxxxxx"                 #
             , nagios_pass    => "xxxxxxxxx"i                #
             , xenapi_user    => 'xxxxxxxxx'                 #
             , carbon_path    => 'xxxxxxxxx'                 #
             , carbon_servers => [ 'carbon1', 'carbon2' ]    #
             , carbon_port    => 2003                        #
             );

# This hash will work as a dispatcher to easily pass around our functions/callbacks.
my %functions = ( api_call         => \&api_call
                , carbon_send      => \&carbon_send
                , parse_rrd        => \&parse_rrd
                , get_member_ip    => \&get_member_ip
                , get_member_name  => \&get_member_name
                , get_pool_members => \&get_pool_members
                , get_vms          => \&get_vms
                , check_master     => \&check_master
                , get_or           => \&get_or
                , fetch_hosts      => \&fetch_hosts
                , main             => \&main
                , whoami           => sub { ( caller(1) )[3] } # Returns the current function name
                , whowasi          => sub { ( caller(2) )[3] } # Returns the current function caller
                );

#{{{ sub api_call(@)
sub api_call(@) {
    AE::log( info => $functions{whoami}->()." called from ".$functions{whowasi}->() );
    my ($callback, $hostref, $method, @params) = @_;
    my %hostref = %{$hostref};
    my $hostname = $hostref;
    $hostname = $hostref->{NAME} if (ref($hostref) eq "HASH" and $hostref->{NAME});
    my $params_string = '';
    $params_string .= '<param><value><string>'.$_.'</string></value></param>' foreach @params;
    AE::log( info  => "api_call called from ".$functions{whowasi}->()." Host: '$hostref->{NAME}' Method: '$method' Params_string: '$params_string'");
    http_request( POST    => "http://$hostname"
                , headers => { Content_Type => 'text/xml' }
                , body    => '<?xml version="1.0" encoding="us-ascii"?><methodCall><methodName>'.$method.'</methodName><params>'.$params_string.'</params></methodCall>'
                , cb      => sub {
                                 my ($body, $headers) = @_;
                                 if ($headers->{Status} =~ /^2/) {
                                    $callback->($body, \%hostref, @params);
                                 } else {
                                     AE::log( error => "api_call Failed. Host: '$hostname' Method: '$method' Params_string: '$params_string'." );
                                     AE::log( error => Dumper $headers );
                                 }
                             }
                )
}
#}}}
#{{{ sub prepare_metrics($)
sub prepare_metrics($) {
    AE::log( info  => 'Entering '.$functions{whoami}->() );
    my $hostref = shift;
    my $now = int(AnyEvent->now);
    my $stats = join( "\n"
                    , "$params{carbon_path}.stats.$hostref->{POOL}.$hostref->{RNAME}.vms $hostref->{HOST_VMS} $now"
                    , "$params{carbon_path}.stats.$hostref->{POOL}.$hostref->{RNAME}.metrics $hostref->{METRICS_COUNT} $now"
                    , "$params{carbon_path}.stats.$hostref->{POOL}.$hostref->{RNAME}.payload_size $hostref->{PAYLOAD_SIZE} $now"
                    , "$params{carbon_path}.stats.$hostref->{POOL}.$hostref->{RNAME}.time ".($now-$startime)." $now"
                    , "\n"
                    );
    return lc($stats);
}
#}}}
#{{{ sub carbon_send($)
sub carbon_send($) {
    AE::log( info  => 'Entering '.$functions{whoami}->() );
    my $hostref = shift;
    my $payload = $hostref;
    $payload = $hostref->{PAYLOAD} if (ref($hostref) eq "HASH" and $hostref->{PAYLOAD});
    foreach my $carbon_server (@{ $params{carbon_servers} }) {
        my $handle; $handle = new AnyEvent::Handle( connect  => [ $carbon_server => $params{carbon_port} ]
                                                  , on_error => sub {
                                                                    AE::log( error => "ON_ERROR sending to $carbon_server:$params{carbon_port}");
                                                                    $handle->destroy;
                                                                }
                                                  , on_drain => sub {
                                                                    AE::log( note  => join ( ", "
                                                                                           , "[$hostref->{POOL}] $hostref->{RNAME}($hostref->{NAME}) got $hostref->{HOST_VMS} VMs with $hostref->{METRICS_COUNT} metrics"
                                                                                           , "carbon payload is $hostref->{PAYLOAD_SIZE} bytes"
                                                                                           , "elapsed time: ".(AnyEvent->now-$startime)." ms."
                                                                                           )
                                                                           );
                                                                    $handle->destroy;
                                                                }
                                                  );
        $payload .= prepare_metrics($hostref);
        $handle->push_write($payload);
    }
}
#}}}
#{{{ sub parse_rrd(@)
sub parse_rrd(@) {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($xml, $hostref) = @_;
    my ($rows, $columns) = $xml =~ />(\d+)<\/rows><columns>(\d+)</;
    AE::log( info => "XML is ".length($xml)." bytes, with $rows rows and $columns columns.");
    my @vs = ();
    push(@vs, $1) while ( $xml =~ /<v>([^<]+)<\/v>/sg );
    my @last_row = @vs[-$columns..-1];
    my $count = 0;
    $hostref->{METRICS_COUNT} = 0;
    while ( $xml =~ /<entry>AVERAGE:vm:([^:]+):([^<]+)<\/entry>/sg ) {
        if ($hostref->{POOLVMS}->{$1} and $hostref->{POOLVMS}->{$1} !~ /Control domain on host/) {
            $hostref->{HOSTVMS}->{$1} = $hostref->{POOLVMS}->{$1};
            my ($vm, $mkey, $mvalue) = ($hostref->{POOLVMS}->{$1}, $2, $last_row[${count}]);
            my $metric = lc("$params{carbon_path}.vms.$hostref->{POOL}.$vm.$mkey $mvalue ".int(AnyEvent->now));
            AE::log( info => $metric );
            $hostref->{PAYLOAD} .= "$metric\n";
            $hostref->{METRICS_COUNT}++;
        }
        ${count}++;
    }
    $hostref->{HOST_VMS} = scalar keys %{ $hostref->{HOSTVMS} };
    $hostref->{PAYLOAD_SIZE} = length($hostref->{PAYLOAD});
    $functions{carbon_send}->($hostref) if $hostref->{PAYLOAD_SIZE};
}
#}}}
#{{{ sub get_member_ip(@)
sub get_member_ip(@) {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($body, $hostref) = @_;
    ($hostref->{NAME}) = $body =~ /<name>Status<\/name><value>Success<\/value><\/member><member><name>Value<\/name><value>([^<]+)<\/value>/;
    AE::log( info => "IP: $hostref->{NAME}" );
    my $epoch = int(AnyEvent->now - 660); # Try to get the 1min metrics
    http_request( GET => "http://$hostref->{NAME}/rrd_updates?session_id=$hostref->{POR}&start=$epoch&interval=60"
                , timeout => 10 # seconds
                , cb => sub {
                           my ($body, $header) = @_;
                           $functions{parse_rrd}->($body, $hostref);
                        }
                );
}
#}}}
#{{{ sub get_member_name(@)
sub get_member_name(@) {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($body, $hostref) = @_;
    ($hostref->{RNAME}) = $body =~ /<name>Status<\/name><value>Success<\/value><\/member><member><name>Value<\/name><value>([^<]+)<\/value>/;
    $hostref->{RNAME} =~ s/\./_/g;
    AE::log( info => "NAME: $hostref->{RNAME}" );
    $functions{api_call}->($functions{get_member_ip}, $hostref, 'host.get_address', $hostref->{POR}, $hostref->{HOR});
}
#}}}
#{{{ sub get_pool_members(@)
sub get_pool_members(@) {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($body, $hostref) = @_;
    while ($body =~ /(OpaqueRef:[^<]+)</sg) {
        $hostref->{HOR} = $1;
        $functions{api_call}->($functions{get_member_name}, $hostref, 'host.get_name_label', $hostref->{POR}, $hostref->{HOR});
    }
}
#}}}
#{{{ sub get_vms(@)
sub get_vms(@) {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($body, $hostref) = @_;
    while ($body =~ /<struct><member>(.+?)<\/member><\/struct>/sg) {
        my $struct = $1;
        my %temp = ();
        while ($struct =~ /<name>([^<]+)<\/name><value>(([^<]+))<\/value>/sg) {
           $temp{$1} = $2;
        }
        if ($temp{uuid} and $temp{name_label} and $temp{name_label}and $temp{power_state} eq 'Running') {
            $hostref->{POOLVMS}->{$temp{uuid}} = $temp{name_label};
        }
    }
    $functions{api_call}->($functions{get_pool_members}, $hostref, 'host.get_all', $hostref->{POR})
}
#}}}
#{{{ sub check_master(@)
sub check_master(@) {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($body, $hostref) = @_;
    if (my ($master) = $body =~ />HOST_IS_SLAVE<\/value><value>([^<]+)</) {
        AE::log( warning => "'$hostref->{NAME}' is slave, pool master is '$master'.");
        $hostref->{NAME} = $master;
        $functions{api_call}->($functions{check_master}, $hostref, 'pool.get_all_records', $hostref->{POR});
    } else {
        ($hostref->{POOL}) = $body =~ /<member><name>name_label<\/name><value>([^<]+)<\/value><\/member>/sg;
        $functions{api_call}->($functions{get_vms}, $hostref, 'VM.get_all_records', $hostref->{POR})
    }
}
#}}}
#{{{ sub get_or(@)
sub get_or(@) {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($body, $hostref) = @_;
    ($hostref->{POR}) = $body =~ /(OpaqueRef:[^<]+)</;
    $functions{api_call}->($functions{check_master}, $hostref, 'pool.get_all_records', $hostref->{POR}) if $hostref->{POR};
}
#}}}
#{{{ sub fetch_hosts(@)
sub fetch_hosts(@) {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($body, $hdr) = @_;
    AE::log( info => Dumper $hdr );
    my %tmphash = ();
    while ($body =~ /check_xen!([^!]+)!([^!]+)!HOSTS/sg) {
        my ($host, $pass,) = (lc($1), $2);
        $tmphash{$host} = $pass;
    }
    foreach my $host (keys %tmphash) {
        $functions{api_call}->($functions{get_or}, { NAME => $host }, 'session.login_with_password', $params{xenapi_user}, $tmphash{$host});
    }
}
#}}}
#{{{ sub main
sub main {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    $startime = AnyEvent->now;
    AE::log( note => "BEGIN on ".int($startime));
    http_request( GET => "http://doctor.uoc.es/nagios/cgi-bin/config.cgi?type=services"
                , headers => { "Authorization" => "Basic ".MIME::Base64::encode("$params{nagios_user}:$params{nagios_pass}", '') }
                , timeout => 10 # seconds
                , sub { $functions{fetch_hosts}->(@_) }
                );
}
#}}}
my $timer; $timer = AnyEvent->timer( after => 0
                                   , interval => $params{interval}
                                   , cb => sub { $functions{main}->() }
                                   );
#Event Loop
AnyEvent->condvar->recv;
