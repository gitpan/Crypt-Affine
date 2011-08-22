use strict; use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME          => 'Crypt::Affine',
    AUTHOR        => q{Mohammad S Anwar <mohammad.anwar@yahoo.com>},
    VERSION_FROM  => 'lib/Crypt/Affine.pm',
    ABSTRACT_FROM => 'lib/Crypt/Affine.pm',
    dist          => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean         => { FILES => 'Crypt-Affine-*' },
    PREREQ_PM     => {
        'Test::More' => 0,
        'Mouse'      => '0.93',
    },
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
);