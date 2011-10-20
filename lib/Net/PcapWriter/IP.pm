use strict;
use warnings;
use Net::PcapWriter::IP;
use Socket qw(AF_INET);
BEGIN { 
	# inet_pton is in Socket since 5.12
	eval { Socket->import('inet_pton');1 }
		or eval { require Socket6; Socket6->import('inet_pton');1 }
		or die "you need either a modern perl or Socket6: $@"
}
use base 'Exporter';
our @EXPORT = qw(ip_chksum ip4_packet);

# write IPv4 packet
sub ip4_packet {
	my ($data,$src,$dst,$protocol) = @_;
	my $hdr = pack('CCnnnCCna4a4',
		0x45, # version 4, len=5 (no options)
		0,    # type of service
		length($data)+20, # total length
		0,0,  # id=0, not fragmented
		128,  # TTL
		$protocol,
		0,    # checksum - computed later
		scalar(inet_pton(AF_INET,$src) || die "no IPv4 $src"),
		scalar(inet_pton(AF_INET,$dst) || die "no IPv4 $dst"),
	);
	substr($hdr,10,2) = pack('n',ip_chksum($hdr));
	return $hdr.$data;
}

sub ip_chksum {
	my $data = pop;
	$data .= "\x00" if length($data) % 2; # padding
	my $sum = 0;
	$sum += $_ for (unpack('n*', $data));
	$sum = ($sum >> 16) + ($sum & 0xffff);
	$sum = ~(($sum >> 16) + $sum) & 0xffff;
	return $sum;
}

1;
