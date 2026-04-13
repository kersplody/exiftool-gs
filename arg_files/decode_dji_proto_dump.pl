#!/usr/bin/env perl

use strict;
use warnings;

use lib 'lib';
use Image::ExifTool qw(:DataAccess :Utils);
use Image::ExifTool::DJI;
use Image::ExifTool::Protobuf;

sub FormatValue($$$$);
sub DecodeProtobuf($$$$$$);

my $file = shift or die "Usage: $0 djmd_stream.bin\n";

open my $fh, '<:raw', $file or die "Can't open $file: $!\n";
local $/;
my $data = <$fh>;
close $fh;

my $et = Image::ExifTool->new;
my $tagTbl = \%Image::ExifTool::DJI::Protobuf;

SetByteOrder('II');
DecodeProtobuf($et, \$data, $tagTbl, '', '', '');

sub DecodeProtobuf($$$$$$)
{
    my ($et, $dataPt, $tagTbl, $prefix, $protoPrefix, $indent) = @_;
    my %dirInfo = ( DataPt => $dataPt, Pos => 0 );

    while ($dirInfo{Pos} < length $$dataPt) {
        my ($buff, $id, $type) = Image::ExifTool::Protobuf::ReadRecord(\%dirInfo);
        last unless defined $buff;

        if ($type == 2 and $buff =~ /\.proto$/) {
            $protoPrefix = substr($buff, 0, -6) . '_';
            print "${indent}Protocol: $buff\n";
        }

        my $tag = "${protoPrefix}${prefix}${id}";
        my $tagInfo = $et->GetTagInfo($tagTbl, $tag);
        my $name = $tagInfo ? ($$tagInfo{Name} || $tag) : $tag;

        if ($type == 2 and $tagInfo and $$tagInfo{SubDirectory}) {
            print "${indent}${name} [$tag]\n";
            my $subTbl = Image::ExifTool::GetTagTable($$tagInfo{SubDirectory}{TagTable});
            DecodeProtobuf($et, \$buff, $subTbl, '', $protoPrefix, "$indent  ");
            next;
        }

        if ($type == 2 and !$tagInfo and Image::ExifTool::Protobuf::IsProtobuf(\$buff)) {
            print "${indent}${tag}\n";
            DecodeProtobuf($et, \$buff, $tagTbl, "${prefix}${id}-", $protoPrefix, "$indent  ");
            next;
        }

        my $val = FormatValue($buff, $type, $tagInfo, \%dirInfo);
        print "${indent}${name} [$tag] = $val\n";
    }
}

sub FormatValue($$$$)
{
    my ($buff, $type, $tagInfo, $dirInfo) = @_;
    my $fmt = $tagInfo ? $$tagInfo{Format} : undef;

    if ($type == 0) {
        return $buff unless defined $fmt;
        if ($fmt eq 'signed') {
            return ($buff & 1) ? -($buff >> 1) - 1 : ($buff >> 1);
        }
        if ($fmt eq 'int64s') {
            return $buff >= 18446744069414584320 ? $buff - 18446744073709551616 : $buff;
        }
        return $buff;
    }

    if ($type == 1) {
        return Image::ExifTool::ReadValue(\$buff, 0, $fmt, undef, length $buff) if defined $fmt;
        return '0x' . unpack('H*', $buff);
    }

    if ($type == 2) {
        if (defined $fmt and $fmt eq 'rational') {
            my %dir = ( DataPt => \$buff, Pos => 0 );
            my $num = Image::ExifTool::Protobuf::VarInt(\%dir);
            my $den = Image::ExifTool::Protobuf::VarInt(\%dir);
            return (defined $num and $den) ? ($num / $den) : 'err';
        }
        if (defined $fmt) {
            return Image::ExifTool::ReadValue(\$buff, 0, $fmt, undef, length $buff);
        }
        return $buff if $buff !~ /[^\r\n\t\x20-\x7e]/;
        return '0x' . unpack('H*', $buff);
    }

    if ($type == 5) {
        return Image::ExifTool::ReadValue(\$buff, 0, $fmt, undef, length $buff) if defined $fmt;
        return '0x' . unpack('H*', $buff);
    }

    return '0x' . unpack('H*', $buff);
}
