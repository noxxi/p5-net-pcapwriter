use strict;
use warnings;

package Net::PcapWriter::TCP;
use fields qw(flow writer l2prefix pktmpl last_timestamp connected);

use Net::PcapWriter::IP;
use Socket qw(AF_INET IPPROTO_TCP);

sub new {
    my ($class,$writer,$src,$sport,$dst,$dport) = @_;
    my $self = fields::new($class);
    $self->{flow} = [
	# src, dst, sport, dport, state, sn
	# state = 0bFfSs: send[F]inack|send[f]in|send[S]ynack|send[s]yn
	# sn gets initialized on sending SYN
	[ $src,$dst,$sport,$dport,0,     undef ],
	[ $dst,$src,$dport,$sport,0,     undef ],
    ];
    $self->{writer} = $writer;
    $self->{last_timestamp} = undef;
    $self->{l2prefix} = $self->{writer}->layer2prefix($src);
    $self->{pktmpl} = [
	ip_packet( undef, $src, $dst, IPPROTO_TCP, 16),
	ip_packet( undef, $dst, $src, IPPROTO_TCP, 16),
    ];
    return $self;
}

sub write_with_flags {
    my ($self,$dir,$data,$flags,$timestamp) = @_;
    $flags ||= {};
    my $flow = $self->{flow}[$dir];

    if ($flags->{syn} and ($flow->[4] & 0b0001) == 0) {
	$flow->[4] |= 0b0001;
	$flow->[5] ||= rand(2**32);
    }
    if ($flags->{fin}) {
	$flow->[4] |= 0b0100;
    }
    if ($flags->{ack}) {
	$flow->[4] |= 0b0010 if ($flow->[4] & 0b0011) == 0b0001; # ACK for SYN
	$flow->[4] |= 0b1000 if ($flow->[4] & 0b1100) == 0b0100; # ACK for FIN
    }

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

    $flow->[5] = (
	$flow->[5]
	+ length($data)
	+ ($flags->{fin}?1:0)
    ) % 2**32;
    $self->{last_timestamp} = $timestamp;
    $self->{writer}->packet(
	$self->{l2prefix} . $self->{pktmpl}[$dir]($tcp),
	$timestamp
    );
}

sub write {
    my ($self,$dir,$data,$timestamp) = @_;
    _connect($self,$timestamp) if ! $self->{connected};
    write_with_flags($self,$dir,$data,undef,$timestamp);
}

sub _connect {
    my ($self,$timestamp) = @_;
    my $flow = $self->{flow};
    goto done if ($flow->[1][4] & 0b11) == 0b11
	&& ($flow->[0][4] & 0b11) == 0b11;

    # client: SYN
    write_with_flags($self,0,'',{ syn => 1 },$timestamp) 
	if ($flow->[0][4] & 0b01) == 0;

    # server: SYN+ACK
    write_with_flags($self,1,'',{ 
	($flow->[1][4] & 0b01) == 0 ? ( syn => 1 ):(),
	($flow->[1][4] & 0b10) == 0 ? ( ack => 1 ):(),
    },$timestamp) if ($flow->[1][4] & 0b11) == 0;

    # client: ACK
    write_with_flags($self,0,'',{ ack => 1 },$timestamp) 
	if ($flow->[0][4] & 0b10) == 0;

    done:
    $self->{connected} = 1;
}

sub _close {
    my ($self,$timestamp) = @_;
    _connect($self,$timestamp) if ! $self->{connected};
    my $flow = $self->{flow};

    # client: FIN
    write_with_flags($self,0,'',{ fin => 1 },$timestamp) 
	if ($flow->[0][4] & 0b0100) == 0;

    # server: FIN+ACK
    write_with_flags($self,1,'',{ 
	($flow->[1][4] & 0b0100) == 0 ? ( fin => 1 ):(),
	($flow->[1][4] & 0b1000) == 0 ? ( ack => 1 ):(),
    },$timestamp) if ($flow->[1][4] & 0b1100) == 0;

    # client: ACK
    write_with_flags($self,0,'',{ ack => 1 },$timestamp) 
	if ($flow->[0][4] & 0b1000) == 0;
}

sub shutdown {
    my ($self,$dir,$timestamp) = @_;
    if (($self->{flow}[$dir][4] & 0b0100) == 0) {
	_connect($self,$timestamp) if ! $self->{connected};
	write_with_flags($self,$dir,'',{ fin => 1 },$timestamp);
	write_with_flags($self,$dir ? 0:1,'',{ ack => 1 },$timestamp);
    }
}

sub ack {
    my ($self,$dir,$timestamp) = @_;
    write_with_flags($self,$dir,'',{ ack => 1 },$timestamp);
}

sub DESTROY {
    my $self = shift;
    $self->_close($self->{last_timestamp});
}


1;


