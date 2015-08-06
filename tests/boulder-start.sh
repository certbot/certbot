#!/bin/sh -xe
# Download and run Boulder instance for integration testing

export GOPATH="${GOPATH:-/tmp/go}"
cd $GOPATH/src/github.com/letsencrypt/boulder
./start.py &
# Hopefully start.py bootstraps before integration test is started...
