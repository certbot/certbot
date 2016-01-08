#!/bin/bash -xe

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL
# are dynamically set at execution

cd letsencrypt
#git checkout v0.1.0     use --branch instead
SAVE="$PIP_EXTRA_INDEX_URL"
unset PIP_EXTRA_INDEX_URL
export PIP_INDEX_URL="https://isnot.org/pip/0.1.0/"
./letsencrypt-auto -v --debug --version 
unset PIP_INDEX_URL

export PIP_EXTRA_INDEX_URL="$SAVE"

if ! ./letsencrypt-auto -v --debug --version | grep 0.1.1 ; then
    echo upgrade appeared to fail
    exit 1
fi
echo upgrade appeared to be successful
