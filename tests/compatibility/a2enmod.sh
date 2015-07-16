#!/bin/bash
# An extremely simplified version of 'a2enmod' for the httpd docker image

enable () {
    echo "LoadModule "$1"_module /usr/local/apache2/modules/mod_"$1".so" >> \
        $APACHE_CONFDIR"/tests.conf"
    available_base="/mods-available/"$1".conf"
    available_conf=$APACHE_CONFDIR$available_base
    enabled_dir=$APACHE_CONFDIR"/mods-enabled"
    enabled_conf=$enabled_dir"/"$1".conf"
    if [ -e "$available_conf" -a -d "$enabled_dir" -a ! -e "$enabled_conf" ]
    then
        ln -s "..$available_base" $enabled_conf
    fi
}

if [ $1 == "ssl" ]
then
    # Enables ssl and all its dependencies
    enable "setenvif"
    enable "mime"
    enable "socache_shmcb"
    enable "ssl"
elif [ $1 == "rewrite" ]
then
    enable "rewrite";
else
    exit 1;
fi
