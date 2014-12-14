use strict;
use warnings;
package Net::PcapWriter::ICMP;
use fields qw(flow writer);
use Net::PcapWriter::IP;
use Socket qw(AF_INET IPPROTO_ICMP);

sub new {
    my ($class,$writer,$src,$dst,$identifier) = @_;
    my $self = fields::new($class);
    $identifier=0 if  (!defined $identifier);
    my $seq=0;
    $self->{flow} = [
        # src, dst, identifier, sequence number
        [ $src,$dst,$identifier,$seq ],
        [ $dst,$src,$identifier,$seq ],
    ];
    $self->{writer} = $writer;
    return $self;
}



sub write {
    my ($self,$dir,$code,$type,$data,$timestamp) = @_;
    my $flow = $self->{flow}[$dir];
    my $checksum = 0;
    my $identifier=$flow->[2];
    my $seq=$flow->[3];


    my $icmp = pack("CCnnna*",
        $code,$type,             # code,type
        $checksum,
        $identifier,$seq,
        $data                        # payload
    );

    $self->{writer}->packet( ip_packet(
        $icmp,
        $flow->[0],
        $flow->[1],
        IPPROTO_ICMP,
        -2,
    ), $timestamp );
}


sub ping {
   my ($self,$dir,$data,$timestamp) = @_;
   # increment seq number
   my $flow = $self->{flow}[0];
   $flow->[3]=$flow->[3]+1;
   $flow = $self->{flow}[1];
   $flow->[3]=$flow->[3]+1;

   $self->write($dir,8,0,$data,$timestamp);
}

sub pong {
   my ($self,$dir,$data,$timestamp) = @_;
   $self->write($dir,0,0,$data,$timestamp);
}



1;

