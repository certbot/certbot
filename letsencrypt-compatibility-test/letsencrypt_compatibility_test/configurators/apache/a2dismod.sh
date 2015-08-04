#!/bin/bash
# An extremely simplified version of `a2enmod` for disabling modules in the
# httpd docker image. First argument is the server_root and the second is the
# module to be disabled.

apache_confdir=$1
module=$2

sed -i "/.*"$module".*/d" "$apache_confdir/test.conf"
enabled_conf="$apache_confdir/mods-enabled/"$module".conf"
if [ -e "$enabled_conf" ]
then
    rm $enabled_conf
fi
