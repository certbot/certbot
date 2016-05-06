#!/bin/bash -xe

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL
# are dynamically set at execution

cd letsencrypt
#git checkout v0.1.0     use --branch instead
SAVE="$PIP_EXTRA_INDEX_URL"
unset PIP_EXTRA_INDEX_URL
export PIP_INDEX_URL="https://isnot.org/pip/0.1.0/"

#OLD_LEAUTO="https://raw.githubusercontent.com/letsencrypt/letsencrypt/5747ab7fd9641986833bad474d71b46a8c589247/letsencrypt-auto"


if ! command -v git ; then
    if [ "$OS_TYPE" = "ubuntu" ] ; then
        sudo apt-get update
    fi
    if ! (  sudo apt-get install -y git || sudo yum install -y git-all || sudo yum install -y git || sudo dnf install -y git ) ; then
        echo git installation failed!
        exit 1
    fi
fi
BRANCH=`git rev-parse --abbrev-ref HEAD`
git checkout v0.1.0
./letsencrypt-auto -v --debug --version
unset PIP_INDEX_URL

export PIP_EXTRA_INDEX_URL="$SAVE"

git checkout -f "$BRANCH"
if ! ./letsencrypt-auto -v --debug --version | grep 0.3.0 ; then
    echo upgrade appeared to fail
    exit 1
fi
echo upgrade appeared to be successful
