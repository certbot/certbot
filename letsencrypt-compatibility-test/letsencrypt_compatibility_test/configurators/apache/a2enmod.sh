#!/bin/bash
# An extremely simplified version of `a2enmod` for enabling modules in the
# httpd docker image. First argument is the server_root and the second is the
# module to be enabled.

confdir=$1
module=$2

echo "LoadModule ${module}_module " \
    "/usr/local/apache2/modules/mod_${module}.so" >> "${confdir}/test.conf"
available_conf=$APACHE_CONFDIR"/mods-available/${module}.conf"
enabled_dir=$APACHE_CONFDIR"/mods-enabled"
enabled_conf=$enabled_dir"/"$1".conf"
if [ -e "$available_conf" -a -d "$enabled_dir" -a ! -e "$enabled_conf" ]
then
    ln -s "..$available_base" $enabled_conf
fi
