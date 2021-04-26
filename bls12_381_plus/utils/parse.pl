#!/usr/bin/perl

use v5.18;

if (@ARGV < 1) {
    die("Must supply input file");
}

open(my $IN, $ARGV[0]) or die("Unable to open file");
binmode($IN);
my $buf = "";
read($IN, $buf, -s $IN);
close($IN);

my @xnum = ();
my @xden = (); 
my @ynum = (); 
my @yden = (); 

my $has_imag = 0;

while ($buf =~ m/\Gk_\((?<index>\d),\d+\)\s+=\s+(?:0x(?<value>[0-9a-f]+\s+(?!\*)))?(?:(?:\+\s+)?0x(?<value2>[0-9a-f]+)\s+\*\s+I\s+)?/gmc) {
    my $index = $+{index};
    my $value = $+{value};
    my $value2 = $+{value2};

    chomp($value);
    chomp($value2);

    my $map = {};

    if (length($value) > 0) {
        while (length($value) < 96) {
            $value = "0" . $value;
        }
        $map->{'real'} = $value;
    }
    if (length($value2) > 0) {
        while (length($value2) < 96) {
            $value2 = "0" . $value2;
        }
        $map->{'imag'} = $value2;
        $has_imag = 1;
    }

    if ($index == 1) {
        push(@xnum, $map);
    } elsif ($index == 2) {
        push(@xden, $map);
    } elsif ($index == 3) {
        push(@ynum, $map);
    } elsif ($index == 4) {
        push(@yden, $map);
    }
}

if (@xnum) {
    output("XNUM", $has_imag, \@xnum);
}
if (@xden) {
    output("XDEN", $has_imag, \@xden);
}
if (@ynum) {
    output("YNUM", $has_imag, \@ynum);
}
if (@yden) {
    output("YDEN", $has_imag, \@yden);
}

sub output {
    my ($label, $has_imag, $arr) = @_;

    my @array = @{$arr};

    if ($has_imag) {
        say "const $label: [Fp2; ". (scalar @array) . "] = [";
        foreach my $xn (@array) {
            say "Fp2{";
            my @chunks = ("0000000000000000") x 6;
            if ($xn->{'real'}) {
                @chunks = $xn->{"real"} =~ m/([0-9a-f]{16})/go;
            }
            say "c0: Fp([";
            pchunk(\@chunks);
            say "]),";
            my @chunks = ("0000000000000000") x 6;
            if ($xn->{'imag'}) {
                @chunks = $xn->{"imag"} =~ m/([0-9a-f]{16})/go;
            }
            say "c1: Fp([";
            pchunk(\@chunks);
            say "]),";
            say "},";
        }
        say "];";
    } else {
        say "const $label: [Fp; ". (scalar @array) ."] = [";
        foreach my $xn (@array) {
            say "Fp([";

            my @chunks = $xn->{"real"} =~ m/([0-9a-f]{16})/go;

            pchunk(\@chunks);

            say "]),";
        }
        say "];";
    }
}

sub pchunk {
    my ($arr) = @_;
    my @chunks = @{$arr};
    foreach my $chunk (reverse @chunks) {
        $chunk =~ s/(....\K(?=.))/_/go;
        say "0x". $chunk ."u64,";
    }
}
