#!/usr/bin/perl

use strict;
use warnings;

use AnyEvent::Strict;
use AnyEvent::HTTP;
use AnyEvent::Log;
use HTTP::Cookies;
use Data::Dumper;
use Cwd 'abs_path';

my $fullpath = abs_path($0);
$AnyEvent::Log::FILTER->level("note");
#$AnyEvent::Log::FILTER->level("debug");
#$AnyEvent::Log::LOG->log_to_file("$fullpath.log");

my %params = ( interval       => 60
             , host           => "arbor.hostname"
             , user           => "xxxxx"
             , pass           => "xxxxx"
             , cookie_jar     =>  HTTP::Cookies->new( autosave => 1 )
             , carbon_path    => 'collector.arbor'
             , carbon_servers => [ 'carbon1', 'carbon2' ]
             , carbon_port    => 2003
             );

# This hash will work as a dispatcher to easily pass around our functions/callbacks.
my %functions = ( main        => \&main
                , fetch       => \&fetch
                , parse       => \&parse
                , carbon_send => \&carbon_send
                , whoami      => sub { ( caller(1) )[3] } # Returns the current function name
                , whowasi     => sub { ( caller(2) )[3] } # Returns the current function caller
                );

#{{{ sub baseunits
sub baseunits {
    my %units = ( 'k' => 1000
                , 'M' => 1000000
                , 'G' => 1000000000
                , 'T' => 1000000000000
                );
    my ($value, $unit)  =  split(' ', shift);
    $value = ($value*$units{$1}) if $unit =~ /([kMGT])[bp]ps/ ;
    return int($value + 0.5);
}
#}}}
#{{{ sub carbon_send
sub carbon_send {
    AE::log( trace => 'Entering '.$functions{whoami}->() );
    my $payload = shift;
    foreach my $carbon_server (@{ $params{carbon_servers} }) {
        my $handle; $handle = new AnyEvent::Handle( connect  => [ $carbon_server => $params{carbon_port} ]
                                                  , on_error => sub { AE::log( error => "ON_ERROR sending to $carbon_server:$params{carbon_port}");
                                                                      $handle->destroy;
                                                                    }
                                                  , on_drain => sub { $handle->destroy; }
                                                  );
        AE::log( debug => "__PAYLOAD ($carbon_server)__\n$payload\n__PAYLOAD ($carbon_server)__" );
        $handle->push_write($payload);
    }
    return 0;
}
#}}}
#{{{ sub parse
sub parse {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($body, $hdr) = @_;
    AE::log( info => Dumper $hdr );
    $body =~ s|\s\s+||g;
    $body =~ s|\n||g;
    $params{payload} = '';
    while ( $body =~ />([^<]+)<\/h4><\/header>.+?<td class="passed_cell">([^<]+)<br>([^<]+)<\/td><td class="dropped_cell">([^<]+)<br>([^<]+)</sg ) {
        my ($name, $passed_bits, $passed_packets, $blocked_bits, $blocked_packets) = (lc($1), $2, $3, $4, $5);
        $name =~ s/\W/_/g;
        $params{payload} .= "$params{carbon_path}.$name.passed.bits ".(baseunits($passed_bits))." $params{startime}\n";
        $params{payload} .= "$params{carbon_path}.$name.passed.packets ".(baseunits($passed_packets))." $params{startime}\n";
        $params{payload} .= "$params{carbon_path}.$name.blocked.bits ".(baseunits($blocked_bits))." $params{startime}\n";
        $params{payload} .= "$params{carbon_path}.$name.blocked.packets ".(baseunits($blocked_packets))." $params{startime}\n";
    }

    $functions{carbon_send}->($params{payload}) if $params{payload};
}
#}}}
#{{{ sub fetch
sub fetch {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    my ($body, $hdr) = @_;
    AE::log( info => Dumper $hdr );
    http_request( GET => "https://$params{host}/groups/list"
                , cookie_jar => $params{cookie_jar}
                , sub { $functions{parse}->(@_) }
                );
}
#}}}
#{{{ sub main
sub main {
    AE::log( info => 'Entering '.$functions{whoami}->() );
    $params{startime} = int(AnyEvent->now);
    AE::log( note => "BEGIN on $params{startime}" );
    http_request( POST => "https://$params{host}/platform/login"
                , body => "username=$params{user}&password=$params{pass}&action=log_in"
                , headers => { 'content-type' => "application/x-www-form-urlencoded" }
                , cookie_jar => $params{cookie_jar}
                , timeout => 30
                , sub { $functions{fetch}->(@_) }
                );
}
#}}}
my $timer; $timer = AnyEvent->timer( after    => 0
                                   , interval => $params{interval}
                                   , cb       => sub { $functions{main}->() }
                                   );
#Event Loop
AnyEvent->condvar->recv;
