#!perl

use strict; use warnings;
use Crypt::Affine;
use Test::More tests => 13;

eval { Crypt::Affine->new(); };
like($@, qr/Attribute \(m\) is required/);

eval { Crypt::Affine->new(r => 1); };
like($@, qr/Attribute \(m\) is required/);

eval { Crypt::Affine->new(m => 1); };
like($@, qr/Attribute \(r\) is required/);

eval { Crypt::Affine->new(r => -1, m => 1); };
like($@, qr/Attribute \(r\) does not pass/);

eval { Crypt::Affine->new(m => -1, r => 1); };
like($@, qr/Attribute \(m\) does not pass/);

eval { Crypt::Affine->new(m => 1, r => 1, reverse => -1); };
like($@, qr/Attribute \(reverse\) does not pass/);

eval { Crypt::Affine->new(m => 1, r => 1, source => 'source.txt'); };
like($@, qr/Attribute \(source\) does not pass/);

eval { Crypt::Affine->new({r => 1}); };
like($@, qr/Attribute \(m\) is required/);

eval { Crypt::Affine->new({m => 1}); };
like($@, qr/Attribute \(r\) is required/);

eval { Crypt::Affine->new({r => -1, m => 1}); };
like($@, qr/Attribute \(r\) does not pass/);

eval { Crypt::Affine->new({m => -1, r => 1}); };
like($@, qr/Attribute \(m\) does not pass/);

eval { Crypt::Affine->new({m => 1, r => 1, reverse => -1}); };
like($@, qr/Attribute \(reverse\) does not pass/);

eval { Crypt::Affine->new({m => 1, r => 1, source => 'source.txt'}); };
like($@, qr/Attribute \(source\) does not pass/);