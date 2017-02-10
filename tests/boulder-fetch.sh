#!/bin/bash
# Download and run Boulder instance for integration testing
set -xe

# Clone Boulder into a GOPATH-style directory structure even if Go isn't
# installed, because Boulder's docker-compose.yml file wll look for it there.
GOPATH=${GOPATH:-$HOME/gopath}
BOULDERPATH=${BOULDERPATH:-$GOPATH/src/github.com/letsencrypt/boulder}
git clone --depth=1 https://github.com/letsencrypt/boulder $BOULDERPATH

cd $BOULDERPATH
FAKE_DNS=$(ifconfig docker0 | grep "inet addr:" | cut -d: -f2 | awk '{ print $1}')
sed -i "s/FAKE_DNS: .*/FAKE_DNS: $FAKE_DNS/" docker-compose.yml
docker-compose up -d
