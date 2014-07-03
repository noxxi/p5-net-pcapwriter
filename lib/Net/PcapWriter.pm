use strict;
use warnings;
package Net::PcapWriter;
use Time::HiRes 'gettimeofday';
use Net::PcapWriter::TCP;
use Net::PcapWriter::UDP;

our $VERSION = '0.711';

sub new {
    my ($class,$file) = @_;
    my $fh;
    if ( $file ) {
	if ( ref($file)) {
	    $fh = $file
	} else {
	    open($fh,'>',$file) or die "open $file: $!";
	}
    } else {
	$fh = \*STDOUT;
    }
    my $self = bless { fh => $fh },$class;
    $self->_header;
    return $self;
}

# write pcap header
sub _header {
    my $self = shift;

    # struct pcap_file_header {
    #     bpf_u_int32 magic;
    #     u_short version_major;
    #     u_short version_minor;
    #     bpf_int32 thiszone; /* gmt to local correction */
    #     bpf_u_int32 sigfigs;    /* accuracy of timestamps */
    #     bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
    #     bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
    # };

    print {$self->{fh}} pack('LSSlLLL',
	0xa1b2c3d4, # magic
	2,4,        # major, minor
	0,0,        # timestamps correction and accuracy
	0xffff,     # snaplen
	1,          # DLT_EN10MB
    );
}

# write pcap packet
sub packet {
    my ($self,$data,$timestamp) = @_;
    $timestamp ||= [ gettimeofday() ];

    # struct pcap_pkthdr {
    #     struct timeval ts;  /* time stamp */
    #     bpf_u_int32 caplen; /* length of portion present */
    #     bpf_u_int32 len;    /* length this packet (off wire) */
    # };

    my ($tsec,$tmsec);
    if (ref($timestamp)) {
	# array like in Time::HiRes
	($tsec,$tmsec) = @$timestamp; 
    } else {
	$tsec = int($timestamp);
	$tmsec = int(($timestamp - $tsec)*1_000_000);
    }

    # add ethernet framing so that we can use DLT_EN10MB
    # DLT_RAW is nicer, but different systems have different ideas about
    # the type id :(
    $data = pack("NnNnna*",
	0,1,0,1, # all macs 0:*
	0x0800, # ETH_TYPE_IP
	$data,
    );

    print {$self->{fh}} pack('LLLLa*',
	$tsec,$tmsec,       # struct timeval ts
	length($data),      # caplen
	length($data),      # len
	$data,              # data
    );
}


# return new TCP connection object
sub tcp_conn {
    my ($self,$src,$sport,$dst,$dport) = @_;
    return Net::PcapWriter::TCP->new($self,$src,$sport,$dst,$dport);
}

# return new UDP connection object
sub udp_conn {
    my ($self,$src,$sport,$dst,$dport) = @_;
    return Net::PcapWriter::UDP->new($self,$src,$sport,$dst,$dport);
}

1;

__END__

=head1 NAME

Net::PcapWriter - simple creation of pcap files from code

=head1 SYNOPSIS

 use Net::PcapWriter;
 my $writer = Net::PcapWriter->new('test.pcap');
 my $conn = $writer->tcp_conn('1.2.3.4',1234,'5.6.7.8',80);

 # this will automatically add syn..synack..ack handshake to pcap
 # each write will be a single packet
 $conn->write(0,"POST / HTTP/1.0\r\nContent-length: 3\r\n\r\n");
 $conn->ack(1); # force ack from server

 # send another packet w/o forcing ack
 $conn->write(0,"abc");

 # client will no longer write
 $conn->shutdown(0);

 # this will automatically add ack to last packet
 $conn->write(1,"HTTP/1.0 200 Ok\r\nContent-length: 10\r\n\r\n");
 $conn->write(1,"0123456789");

 # will automatically add remaining FIN+ACK
 undef $conn;

 # write some UDP packets with IPv6
 $conn = $writer->udp_conn('dead::beaf',1234,'beaf::dead',53);
 $conn->write(0,"....");
 $conn->write(1,"....");

=head1 DESCRIPTION

With L<Net::PcapWriter> it is possible to create pcap files within a program
without capturing any data. This is useful for setting up test data without
setting up the needed infrastructure for data creation and capturing.

The following methods are supported:

=over 4

=item $class->new([$filename|$handle])

Creates new object.
If file name is given it will be opened for writing, if file handle is given it
will be used. Otherwise the pcap data will be written to STDOUT.
Will write pcap header for DLT_RAW to pcap file.

=item $writer->packet($pkt,[$timestamp])

Will write raw IP packet $pkt with $timestamp in pcap file.
$timestamp can be C<time_t> (seconds), float (like C<time_t>, but with higher
resolution) or C<<[$sec,$msec]>> like in C<<struct timeval>>.
If $timestamp is not given will use C<Time::HiRes::gettimeofday>.

=item $writer->tcp_conn($src,$sport,$dst,$dport)

Will return C<Net::PcapWriter::TCP> object, which then provides the following
methods:

=over 8

=item $tcpconn->write($dir,$data,[$timestamp])

Will write the given data for the direction C<$dir> (0 are data from client to
server, 1 the other way). Will write TCP handshake if not done yet.

=item $tcpconn->ack($dir)

Will write an empty message with an ACK from direction C<$dir>.

=item $tcpconn->shutdown($dir)

Will add FIN+ACK for shutdown from direction C<$dir> unless already done.

=item undef $tcpconn

Will call shutdown for both C<$dir> before destroying connection object.

=back

=item $writer->udp_conn($src,$sport,$dst,$dport)

Will return C<Net::PcapWriter::UDP> object, which then provides the following
methods:

=item $tcpconn->write($dir,$data,[$timestamp])

Will write the given data for the direction C<$dir> (0 are data from client to
server, 1 the other way).

=back

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>
