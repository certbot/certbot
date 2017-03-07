#!/bin/bash -xe

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL
# are dynamically set at execution

cd letsencrypt

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
# 0.4.1 is the oldest version of letsencrypt-auto that can be used because
# it's the first version that both pins package versions and properly supports
# --no-self-upgrade.
git checkout -f v0.4.1
if ! ./letsencrypt-auto -v --debug --version --no-self-upgrade 2>&1 | grep 0.4.1 ; then
    echo initial installation appeared to fail
    exit 1
fi

git checkout -f "$BRANCH"
EXPECTED_VERSION=$(grep -m1 LE_AUTO_VERSION letsencrypt-auto | cut -d\" -f2)
if ! ./letsencrypt-auto -v --debug --version --no-self-upgrade 2>&1 | grep $EXPECTED_VERSION ; then
    echo upgrade appeared to fail
    exit 1
fi
echo upgrade appeared to be successful
