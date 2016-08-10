#!/bin/bash -x

# >>>> only tested on Ubuntu 14.04LTS <<<<

# Check out special branch until latest docker changes land in Boulder master.
git clone -b docker-integration https://github.com/letsencrypt/boulder $BOULDERPATH
cd $BOULDERPATH
FAKE_DNS=$(ifconfig docker0 | grep "inet addr:" | cut -d: -f2 | awk '{ print $1}')
sed -i "s/FAKE_DNS: .*/FAKE_DNS: $FAKE_DNS/" docker-compose.yml
docker-compose up -d
