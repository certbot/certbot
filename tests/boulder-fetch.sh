#!/bin/bash
# Download and run Boulder instance for integration testing
set -xe

# Check out special branch until latest docker changes land in Boulder master.
git clone --depth=1 https://github.com/letsencrypt/boulder $BOULDERPATH
cd $BOULDERPATH
FAKE_DNS=$(ifconfig docker0 | grep "inet addr:" | cut -d: -f2 | awk '{ print $1}')
sed -i "s/FAKE_DNS: .*/FAKE_DNS: $FAKE_DNS/" docker-compose.yml
docker-compose up -d
