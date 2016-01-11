#!/bin/bash -xe

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL
# are dynamically set at execution

cd letsencrypt/letsencrypt
VERSION=`sed -n "s/^__version__\s*=\s*[\"']\(.*\)[\"']/\1/p" __init__.py`
cd ../letsencrypt_auto

RunLetsencryptAuto() {
    OUTPUT=`./letsencrypt-auto -v --debug --version 2>&1`

    if [[ $OUTPUT != *"$VERSION"* ]] ; then
        echo letsencrypt-auto failed to run
        exit 1
    fi
}

RunLetsencryptAuto
RunLetsencryptAuto
if [[ $OUTPUT == *"Installing Python packages"* ]] ; then
    echo second run of letsencrypt-auto reinstalled Python packages
    exit 1
fi

echo letsencrypt-auto worked!
