#!/bin/bash
# An extremely simplified version of `a2enmod` for enabling modules in the
# httpd docker image. First argument is the Apache ServerRoot which should be
# an absolute path. The second is the module to be enabled, such as `ssl`.

confdir=$1
module=$2

echo "LoadModule ${module}_module " \
    "/usr/local/apache2/modules/mod_${module}.so" >> "${confdir}/test.conf"
availbase="/mods-available/${module}.conf"
availconf=$confdir$availbase
enabldir="$confdir/mods-enabled"
enablconf="$enabldir/${module}.conf"
if [ -e $availconf -a -d $enabldir -a ! -e $enablconf ]
then
    ln -s "..$availbase" $enablconf
fi
