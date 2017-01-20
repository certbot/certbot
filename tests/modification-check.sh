#!/bin/bash

temp_dir=`mktemp -d`

# Script should be run from Certbot's root directory

SCRIPT_PATH=`dirname $0`
SCRIPT_PATH=`readlink -f $SCRIPT_PATH`
FLAG=false

# Compare root letsencrypt-auto and certbot-auto with published versions

cp letsencrypt-auto ${temp_dir}/letsencrypt-to-be-checked
cp certbot-auto ${temp_dir}/certbot-to-be-checked

cp letsencrypt-auto-source/pieces/fetch.py ${temp_dir}/fetch.py
cd ${temp_dir}

LATEST_VERSION=`python fetch.py --latest-version`
python fetch.py --le-auto-script v${LATEST_VERSION}

cmp -s letsencrypt-auto letsencrypt-to-be-checked

if [ $? != 0 ]; then
	echo "Root letsencrypt-auto has changed."
	FLAG=true
else
	echo "Root letsencrypt-auto is unchanged."
fi

cmp -s letsencrypt-auto certbot-to-be-checked

if [ $? != 0 ]; then
	echo "Root certbot-auto has changed."
	FLAG=true
else
	echo "Root certbot-auto is unchanged."
fi

# Cleanup
rm ${temp_dir}/*
cd ${SCRIPT_PATH}/../

# Compare letsencrypt-auto-source/letsencrypt-auto with output of build.py

cp letsencrypt-auto-source/letsencrypt-auto ${temp_dir}/original-lea
python letsencrypt-auto-source/build.py
cp letsencrypt-auto-source/letsencrypt-auto ${temp_dir}/build-lea
cp ${temp_dir}/original-lea letsencrypt-auto-source/letsencrypt-auto

cd $temp_dir

cmp -s original-lea build-lea

if [ $? != 0 ]; then
	echo "letsencrypt-auto-source/letsencrypt-auto doesn't match output of \
build.py."
	FLAG=true
else
	echo "letsencrypt-auto-source/letsencrypt-auto matches output of \
build.py."
fi

rm -rf $temp_dir

if $FLAG ; then
	exit 1
fi
