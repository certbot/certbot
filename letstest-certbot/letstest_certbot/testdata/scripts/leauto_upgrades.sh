#!/bin/bash -xe

if ! command -v git ; then
    apt-get update && apt-get install git -y || sudo yum install -y git-all || sudo yum install -y git || sudo dnf install -y git
fi
BRANCH=`git rev-parse --abbrev-ref HEAD`
# 0.4.1 is the oldest version of letsencrypt-auto that can be used because
# it's the first version that both pins package versions and properly supports
# --no-self-upgrade.
git checkout -f v0.4.1
if ! ./letsencrypt-auto -v --debug --version --no-self-upgrade 2>&1 | grep 0.4.1 ; then
    ./letsencrypt-auto -v --debug --version --no-self-upgrade || true
    echo initial installation appeared to fail
    sleep 1200
    exit 1
fi

git checkout -f "$BRANCH"
EXPECTED_VERSION=$(grep -m1 LE_AUTO_VERSION letsencrypt-auto | cut -d\" -f2)
if ! ./letsencrypt-auto -v --debug --version --no-self-upgrade 2>&1 | grep $EXPECTED_VERSION ; then
    echo upgrade appeared to fail
    exit 1
fi
echo upgrade appeared to be successful
