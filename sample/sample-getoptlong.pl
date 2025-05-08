#!/usr/bin/perl

use v5.28;
use strict;
use warnings;
use Getopt::Long qw(:config posix_default no_ignore_case gnu_compat);

my $data    = '';
my $length  = 0;
my $verbose = 0;
my $very    = 0;

GetOptions(
    'file|f=s'   => \$data,       # string
    'length|l=i' => \$length,     # numeric
    'verbose|v'  => \$verbose,    # flag
    'very|V'     => \$very,
) or die "Error in command line arguments\n";

print "data:    '$data'\n";
print "length:  $length\n";
print "verbose: $verbose\n";
print "very:    $very\n";

print "args: @ARGV\n";

# support on:
#   perltidy -l 100 --check-syntax --paren-tightness=2
#   perlcritic -4
# vim: set ts=4 sw=4 sts=0 expandtab:
