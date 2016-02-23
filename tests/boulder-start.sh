#!/bin/bash

export GOPATH="${GOPATH:-/tmp/go}"
export GOBIN="$GOPATH/bin"
export PATH="$GOPATH/bin:$PATH"

./tests/boulder-fetch.sh

cd $GOPATH/src/github.com/letsencrypt/boulder
./start.py
