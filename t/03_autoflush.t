use strict;
use warnings;
use Net::PcapWriter;
use Test;
use File::Temp 'tempfile';
BEGIN { plan tests => 4 }

my ($fh, $filename) = tempfile();
my $w = Net::PcapWriter->new($fh);

my $conn = $w->tcp_conn('1.2.3.4',2000,'5.6.7.8',80) or die;
$conn->write(0,"GET / HTTP/1.0\r\n\r\n");
$conn->write(1,"HTTP/1.0 200 ok\r\nContent-length: 0\r\n\r\n");
undef $conn;

# output of tcpdump can be different on each platform, and maybe
# no tcpdump is installed. So just check some stuff in file

open my $f, '<', $filename or die "open $filename: $!";
local $/ = undef;
my $pcap = <$f>;

ok( length($pcap) == 710 );
ok( substr($pcap,0x130,18) eq "GET / HTTP/1.0\r\n\r\n" );
ok( substr($pcap,0xce,8) eq pack("CCCCCCCC",1..8));
ok( substr($pcap,0x14,1) eq "\001");
