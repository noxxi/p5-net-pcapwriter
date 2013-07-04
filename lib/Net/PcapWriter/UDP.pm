
use strict;
use warnings;
package Net::PcapWriter::UDP;
use fields qw(flow writer);
use Net::PcapWriter::IP;
use Socket qw(AF_INET IPPROTO_UDP);

sub new {
	my ($class,$writer,$src,$sport,$dst,$dport) = @_;
	my $self = fields::new($class);
	$self->{flow} = [
		# src, dst, sport, dport
		[ $src,$dst,$sport,$dport ],
		[ $dst,$src,$dport,$sport ],
	];
	$self->{writer} = $writer;
	return $self;
}

sub write {
	my ($self,$dir,$data,$timestamp) = @_;
	my $flow = $self->{flow}[$dir];

	my $udp = pack("nnnna*",
		$flow->[2],$flow->[3],       # sport,dport
		length($data)+8,
		0,                           # checksum
		$data                        # payload
	);
	my $ckdata = pack('a4a4Cna*',
		scalar(inet_pton(AF_INET,$flow->[0]) || die "no IPv4"), # src
		scalar(inet_pton(AF_INET,$flow->[1]) || die "no IPv4"), # dst
		0,17,length($udp),                    # proto + len
		$udp
	);
	substr($udp,6,2) = pack('n',ip_chksum($ckdata));

	$self->{writer}->packet( ip4_packet(
		$udp,
		$flow->[0],
		$flow->[1],
		IPPROTO_UDP,
	), $timestamp );
}

1;


