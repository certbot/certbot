#!/bin/sh -xe
# Download and run Boulder instance for integration testing

export GOPATH="${GOPATH:-/tmp/go}"

# $ go get github.com/letsencrypt/boulder
# package github.com/letsencrypt/boulder
#         imports github.com/letsencrypt/boulder
#         imports github.com/letsencrypt/boulder: no buildable Go source files in /tmp/go/src/github.com/letsencrypt/boulder

go get -d github.com/letsencrypt/boulder/cmd/boulder
cd $GOPATH/src/github.com/letsencrypt/boulder
make -j4  # Travis has 2 cores per build instance.
if [ "$1" = "amqp" ];
then
    ./start.py &
else
    ./start.sh &
fi
# Hopefully start.py/start.sh bootstraps before integration test is started...
