use strict; use warnings;
use Module::Build;

my $builder = Module::Build->new(
    sign              => 1,
    module_name       => 'Crypt::Affine',
    license           => 'perl',
    dist_author       => q{Mohammad S Anwar <mohammad.anwar@yahoo.com>},
    dist_version_from => 'lib/Crypt/Affine.pm',
    add_to_cleanup    => [ 'Crypt-Affine-*' ],    
    build_requires    => {
        'Test::More'  => 0,
        'Mouse'       => '0.93',
    },
);

$builder->create_build_script();