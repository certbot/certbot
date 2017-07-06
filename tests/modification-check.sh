#!/bin/bash -e

temp_dir=`mktemp -d`
trap "rm -rf $temp_dir" EXIT

# cd to repo root
cd $(dirname $(dirname $(readlink -f $0)))
FLAG=false

if ! cmp -s certbot-auto letsencrypt-auto; then
    echo "Root certbot-auto and letsencrypt-auto differ."
    FLAG=true
else
    cp certbot-auto "$temp_dir/local-auto"
    cp letsencrypt-auto-source/pieces/fetch.py "$temp_dir/fetch.py"
    cd $temp_dir

    # Compare file against current version in the target branch
    BRANCH=${TRAVIS_BRANCH:-master}
    URL="https://raw.githubusercontent.com/certbot/certbot/$BRANCH/certbot-auto"
    curl -sS $URL > certbot-auto
    if cmp -s certbot-auto local-auto; then
        echo "Root *-auto were unchanged."
    else
        # Compare file against the latest released version
        python fetch.py --le-auto-script "v$(python fetch.py --latest-version)"
        if cmp -s letsencrypt-auto local-auto; then
            echo "Root *-auto were updated to the latest version."
        else
            echo "Root *-auto have unexpected changes."
            FLAG=true
        fi
    fi
    cd ~-
fi

# Compare letsencrypt-auto-source/letsencrypt-auto with output of build.py

cp letsencrypt-auto-source/letsencrypt-auto ${temp_dir}/original-lea
python letsencrypt-auto-source/build.py
cp letsencrypt-auto-source/letsencrypt-auto ${temp_dir}/build-lea
cp ${temp_dir}/original-lea letsencrypt-auto-source/letsencrypt-auto

cd $temp_dir

if ! cmp -s original-lea build-lea; then
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
