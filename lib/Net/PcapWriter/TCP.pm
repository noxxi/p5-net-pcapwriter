
use strict;
use warnings;
package Net::PcapWriter::TCP;
use fields qw(flow writer last_timestamp);
use Net::PcapWriter::IP;
use Socket qw(AF_INET IPPROTO_TCP);
BEGIN { 
	# inet_pton is in Socket since 5.12
	eval { Socket->import('inet_pton');1 }
		or eval { require Socket6; Socket6->import('inet_pton');1 }
		or die "you need either a modern perl or Socket6"
}

sub new {
	my ($class,$writer,$src,$sport,$dst,$dport) = @_;
	my $self = fields::new($class);
	$self->{flow} = [
		# src, dst, sport, dport, state, sn
		# state = 0bFfSs: got[F]inack|send[f]in|got[S]ynack|send[s]yn
		# sn gets initialized on sending SYN
		[ $src,$dst,$sport,$dport,0,     undef ],
		[ $dst,$src,$dport,$sport,0,     undef ],
	];
	$self->{writer} = $writer;
	$self->{last_timestamp} = undef;
	return $self;
}

sub write_with_flags {
	my ($self,$dir,$data,$flags,$timestamp) = @_;
	$flags ||= {};
	my $flow = $self->{flow}[$dir];
	my $sn = $flow->[5];
	my $ack = $self->{flow}[$dir?0:1][5];
	$flags->{ack} = 1 if defined $ack;

	my $f = 0;
	$f |= 0b000100 if $flags->{rst};
	$f |= 0b001000 if $flags->{psh};
	$f |= 0b010000 if $flags->{ack};
	$f |= 0b100000 if $flags->{urg};
	$f |= 0b000001 if $flags->{fin};
	if ( $flags->{syn} ) {
		$f |= 0b000010;
		$sn = ($sn-1) % 2**32;
	}

	my $tcp = pack("nnNNCCnnna*",
		$flow->[2],$flow->[3],       # sport,dport
		$sn,                         # sn
		$ack||0,                     # ack
		0x50,                        # size of TCP header >> 4
		$f,                          # flags
		$flags->{window} || 2**15,   # window
		0,                           # checksum computed later
		$flags->{urg}||0,            # urg pointer
		$data                        # payload
	);
	my $ckdata = pack('a4a4CCna*',
		scalar(inet_pton(AF_INET,$flow->[0]) || die "no IPv4"), # src
		scalar(inet_pton(AF_INET,$flow->[1]) || die "no IPv4"), # dst
		0,6,length($tcp),                    # proto + tcplen
		$tcp
	);
	substr($tcp,18,2) = pack('n',ip_chksum($ckdata));

	$flow->[5] = ( 
		$flow->[5] 
		+ length($data) 
		+ ($flags->{fin}?1:0) 
	) % 2**32;
	$self->{last_timestamp} = $timestamp;
	$self->{writer}->packet( ip4_packet(
		$tcp,
		$flow->[0],
		$flow->[1],
		IPPROTO_TCP,
		$timestamp
	));
}

sub write {
	my ($self,$dir,$data,$timestamp) = @_;
	$self->_connect($timestamp);
	$self->write_with_flags($dir,$data,undef,$timestamp);
}

sub _connect {
	my ($self,$timestamp) = @_;
	if ( not $self->{flow}[0][4] & 0b01 ) {
		$self->{flow}[0][5] ||= rand(2**32);
		$self->write_with_flags(0,'',{ syn => 1 },$timestamp);
		$self->{flow}[0][4] |= 0b01;
	}
	if ( not $self->{flow}[1][4] & 0b01 ) {
		$self->{flow}[1][5] ||= rand(2**32);
		$self->write_with_flags(1,'',{ syn => 1, ack => 1 },$timestamp);
		$self->{flow}[0][4] |= 0b10;
		$self->{flow}[1][4] |= 0b01;
	}
	if ( not $self->{flow}[1][4] & 0b10 ) {
		$self->ack(0,$timestamp);
		$self->{flow}[1][4] |= 0b10;
	}
}

sub _close {
	my ($self,$dir,$timestamp) = @_;
	$self->shutdown($dir||0,$timestamp);
	$self->shutdown($dir?0:1,$timestamp);
}

sub shutdown {
	my ($self,$dir,$timestamp) = @_;
	if ( not $self->{flow}[$dir][4] & 0b0100 ) {
		$self->write_with_flags($dir,'',{ fin => 1 },$timestamp);
		$self->ack($dir?0:1,$timestamp);
		$self->{flow}[$dir][4] |= 0b0100;
		$self->{flow}[$dir][4] |= 0b1000;
	}
}

sub ack {
	my ($self,$dir,$timestamp) = @_;
	$self->write_with_flags($dir,'',{ ack => 1 },$timestamp);
}

sub DESTROY {
	my $self = shift;
	$self->_connect(undef,$self->{last_timestamp});
	$self->_close(undef,$self->{last_timestamp});
}


1;


