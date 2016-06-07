#!/bin/bash
# Download and run Boulder instance for integration testing
set -xe

# Check out special branch until latest docker changes land in Boulder master.
git clone -b docker-integration https://github.com/letsencrypt/boulder $BOULDERPATH
cd $BOULDERPATH
sed -i 's/FAKE_DNS: .*/FAKE_DNS: 172.17.42.1/' docker-compose.yml
docker-compose up -d

