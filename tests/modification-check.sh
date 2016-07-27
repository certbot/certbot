#!/bin/bash

temp_dir=`mktemp -d`

# Script should be run from Certbot's root directory
cp letsencrypt-auto ${temp_dir}/to-be-checked
cp letsencrypt-auto-source/pieces/fetch.py ${temp_dir}/fetch.py
cd ${temp_dir}

LATEST_VERSION=`python fetch.py --latest-version`
python fetch.py --le-auto-script v${LATEST_VERSION}

cmp -s letsencrypt-auto to-be-checked

if [ $? != 0 ]; then
	echo "Root letsencrypt-auto has changed."
	rm -rf temp_dir
	exit 1
fi

rm -rf temp_dir
