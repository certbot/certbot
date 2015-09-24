#!/bin/bash
# Download and run Boulder instance for integration testing


# ugh, go version output is like:
# go version go1.4.2 linux/amd64
GOVER=`go version | cut -d" " -f3 | cut -do -f2`  

# version comparison
function verlte {
    [  "$1" = "`echo -e "$1\n$2" | sort -V | head -n1`" ]
}

if ! verlte 1.5 "$GOVER" ; then
  echo "We require go version 1.5 or later; you have... $GOVER"
  exit 1
fi

set -xe

export GOPATH="${GOPATH:-/tmp/go}"
export PATH="$GOPATH/bin:$PATH"

# `/...` avoids `no buildable Go source files` errors, for more info
# see `go help packages`
go get -d github.com/letsencrypt/boulder/...
cd $GOPATH/src/github.com/letsencrypt/boulder
# goose is needed for ./test/create_db.sh
if ! go get bitbucket.org/liamstask/goose/cmd/goose ; then
  echo Problems installing goose... perhaps rm -rf \$GOPATH \("$GOPATH"\)
  echo and try again...
  exit 1
fi
./test/create_db.sh
./start.py &
# Hopefully start.py bootstraps before integration test is started...
