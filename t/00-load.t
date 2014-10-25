#!perl

use Test::More tests => 2;
BEGIN {
    use_ok('Crypt::Affine')         || print "Bail out!";
    use_ok('Crypt::Affine::Params') || print "Bail out!";
}
