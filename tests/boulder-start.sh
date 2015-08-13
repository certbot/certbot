#!/bin/sh -x
# Download and run Boulder instance for integration testing

export GOPATH="${GOPATH:-/tmp/go}"

go get -d github.com/letsencrypt/boulder
cd $GOPATH/src/github.com/letsencrypt/boulder

if [ "${TRAVIS}" == "true" ]; then
  ./test/create_db.sh || die "unable to create the boulder database with test/create_db.sh"
fi

./start.py &
# Hopefully start.py bootstraps before integration test is started...
