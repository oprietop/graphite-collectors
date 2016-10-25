#!/usr/bin/perl

use warnings;
use strict;
use Scalar::Util qw(looks_like_number);
use Net::OpenSSH;
use IO::Socket::INET;
use LWP::UserAgent;
use HTML::Entities; # decode_entities
#$Net::OpenSSH::debug |= 16; # Debug

my %params = ( interval       => 60                      #
             , skip_empty     => 1                       #
             , nagios_url     => "http://nagios/nagios"  #
             , nagios_user    => "user"                  #
             , nagios_pass    => "pass"                  #
             , nagios_note    => '\[statgrab\]'          #
             , carbon_path    => 'path.hosts_ssh'        #
             , carbon_servers => [ 'carbon1' ]           #
             , carbon_port    => 2003                    #
             , carbon_proto   => 'tcp'                   #
             , debug          => 0                       #
             );

# {{{ sub carbon_send
sub carbon_send {
    my $payload = shift;
    # Send to every server.
    foreach my $carbon_server (@{ $params{carbon_servers} }) {
        # We will try 3 times.
        foreach ( 1..3 ) {
            my $sock = IO::Socket::INET->new( PeerAddr => $carbon_server
                                            , PeerPort => $params{carbon_port}
                                            , Proto    => $params{carbon_proto}
                                            , Timeout  => 5
                                            );
            print "EE [carbon_send] Unable to connect to $carbon_server:$params{carbon_port} $params{carbon_proto}, $!." unless $sock;
            # leave the loop if everything went fine.
            last if $sock->send($payload) or print "EE [carbon_send] Error sending: $!\n";
        }
    }
}
# }}}
# {{{ sub parse_results
sub parse_results {
    $params{payload} = "";
    foreach my $host (sort keys %{ $params{nagios_results} }) {
        my $prefix = "$params{carbon_path}.$params{nagios_results}{$host}{PREFIX}.$params{nagios_results}{$host}{NAME}";
        open(my $data, '<', "/tmp/$host") or die "EE Could not open /tmp/$host, $!\n";
        my $valid = "";
        while(my $line = <$data>) {
            chomp($line);
            my ($metric, $value) = split(' = ', $line);

            # Sanitize value
            next unless looks_like_number($value);    # value can only be a number
            $value = ($value*1000) if $value =~ /\./; # and a integer

            # Sanitize metric
            $metric = lc("$prefix\.$metric");     # Lowercase full metric
            $metric =~ s/[^\w\-\.,_|(){}\\]+/_/g; # Only allowed characters
            $metric =~ s/_+/_/g;                  # Clean it a bit

            # Add it to the carbon payload
            $valid .= "$metric $value $params{last_run}\n";
        }
        close($data);
        my $length = length($valid);
        print "WW [parse_results] $params{nagios_results}{$host}{PREFIX}.$params{nagios_results}{$host}{NAME} ($length)\n" if $length < 1000;
        $params{payload} .= $valid;
    }
    my $paylength = length($params{payload});
    print "II [parse_results] Payload length is ($paylength)\n";
}
# }}}
# {{{ sub ssh_connect
sub ssh_connect {
    # Connect to every host... at once.
    my %conn = map { $_ => Net::OpenSSH->new( $params{nagios_results}{$_}{IP}
                                            , port                  => $params{nagios_results}{$_}{PORT} || 22
                                            , async                 => 1
                                            , timeout               => 10
                                            , master_stderr_discard => 1
                                            , master_opts           => [ -o => "StrictHostKeyChecking=no"
                                                                       , -o => "ConnectionAttempts=1"
                                                                       , -o => "ConnectTimeout=10"
                                                                       ]
                                            , default_ssh_opts      => ['-oConnectionAttempts=0'],
                                            , user                  => 'root'
                                            , key_path              => "/root/statgrab.private"
                                            ) } keys %{ $params{nagios_results} };

    # Launch commands to each host reusing the previous.
    my @pid;
    foreach my $host (sort {rand() <=> 0.5} keys %{ $params{nagios_results} }) {
        open(my $fh, '>', "/tmp/$host") or die "Unable to create file: $!";
        my $pid = $conn{$host}->spawn( { stdout_fh => $fh, stderr_fh => $fh });
        push(@pid, $pid) if $pid;
    }

    # Wait for all the commands to finish.
    waitpid($_, 0) for @pid;
    print "II [ssh_connect] Finished SSH connections in ".(time() - $params{last_run})."s\n";
}
# }}}
# {{{ sub fetch_hosts
sub fetch_hosts {
    # Connect to the source and fetch all the hosts.
    my $ua = LWP::UserAgent->new(timeout => 5);
    my $req = HTTP::Request->new( GET => "$params{nagios_url}/cgi-bin/config.cgi?type=hosts");
    $req->authorization_basic("$params{nagios_user}", "$params{nagios_pass}");
    my $res = $ua->request($req);
    my $body = decode_entities($res->content);
    # Our info should be into TR tags.
    while ($body =~ /<TR(.+?)TR>/sg) {
        my $tr = $1;
        # It must contain our flag
        next unless $tr =~ qr/$params{nagios_note}(.*?)</;
        # Get the prefix if included.
        my $paramlist = $1;
        my $prefix = 'none';
        $prefix = $1 if $paramlist =~ /prefix\(([\w_-]+)\)/;
        # Get the name and ip address of the host and populate our results hash;
        if ($tr =~ /<TD CLASS='\w+'>([^<]+)<\/TD>.<TD CLASS='\w+'>([\d\.]+)<\/TD>/sg) {
            my ($name, $ip) = ($1, $2);
            $params{nagios_results}{$ip} = { IP     => $ip
                                           , NAME   => $name
                                           , PREFIX => $prefix
                                           };
        }
    }

    my $host_count = scalar values %{ $params{nagios_results} };

    # Keep a backup of our hosts so we can continue working even if the source fails.
    if ($host_count) {
        print "II [fetch_hosts] Got $host_count hosts from $params{nagios_url}\n";
        # Cache the current results.
        $params{nagios_cache} = $params{nagios_results};
    } elsif ($params{nagios_cache}) {
        # Use the cached results.
        $host_count = scalar values %{ $params{nagios_cache} };
        $params{nagios_results} = $params{nagios_cache};
        print "WW [fetch_hosts] No results from $params{nagios_url}, using the $host_count cached devices.";
    } else {
        # It failed miserably, better luck next time...
        print "WW [fetch_hosts] No results from $params{nagios_url} and empty cache, waiting...";
        return 1;
    }
}
# }}}

sub main {
    my $run_count = 0;
    while (1) {
        # Get the initial timestamp and print what we're doing.
        $params{last_run} = time();
        my $next_run = $params{last_run} + $params{interval};
        ${run_count}++;
        print "II [main] Begin ${run_count}th run @ ".scalar localtime($params{last_run})." ($params{last_run})\n";

        # Fetch the hosts to process.
        fetch_hosts;

        # Initiate and keep a connection to each host.
        ssh_connect;

        # Parse the results if any.
        parse_results;

        # Send the parsed results to the carbon daemons.
        carbon_send($params{payload});

        # Wait the remaining interval time, if any.
        while ((my $timeleft = ($next_run - time())) > 0) {
            my $exectime = ($params{interval}-${timeleft});
            print "II [main] ${run_count}th run took ${exectime}s, sleeping for ${timeleft}s.\n";
            sleep ($timeleft);
        }
    } #while
} # main

main();

