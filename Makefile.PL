use ExtUtils::MakeMaker;
require 5.8.8;

# inet_pton is in Socket since 5.12
my %prereq;
require Socket;
$prereq{Socket6} = 0 if ! eval { Socket->import('inet_pton');1 };

WriteMakefile(
	NAME => 'Net::PcapWriter',
	VERSION_FROM => 'lib/Net/PcapWriter.pm',
);
