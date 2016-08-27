#!/bin/bash

temp_dir=`mktemp -d`

# Script should be run from Certbot's root directory
cp letsencrypt-auto ${temp_dir}/letsencrypt-to-be-checked
cp certbot-auto ${temp_dir}/certbot-to-be-checked

cp letsencrypt-auto-source/pieces/fetch.py ${temp_dir}/fetch.py
cd ${temp_dir}

LATEST_VERSION=`python fetch.py --latest-version`
python fetch.py --le-auto-script v${LATEST_VERSION}

cmp -s letsencrypt-auto letsencrypt-to-be-checked

if [ $? != 0 ]; then
	echo "Root letsencrypt-auto has changed."
	rm -rf temp_dir
	exit 1
else
	echo "Root letsencrypt-auto is unchanged."
fi

cmp -s letsencrypt-auto certbot-to-be-checked

if [ $? != 0 ]; then
	echo "Root certbot-auto has changed."
	rm -rf temp_dir
	exit 1
else
	echo "Root certbot-auto is unchanged."
fi

rm -rf temp_dir
