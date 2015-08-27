#!/bin/sh -xe
# Download and run Boulder instance for integration testing

export GOPATH="${GOPATH:-/tmp/go}"

# `/...` avoids `no buildable Go source files` errors, for more info
# see `go help packages`
go get -d github.com/letsencrypt/boulder/...
cd $GOPATH/src/github.com/letsencrypt/boulder
./test/create_db.sh
./start.py &
# Hopefully start.py bootstraps before integration test is started...
