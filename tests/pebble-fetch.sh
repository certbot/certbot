#!/bin/bash
# Download and run Pebble instance for integration testing
set -xe

export GOPATH=${GOPATH:-$HOME/gopath}
PEBBLEPATH=${PEBBLEPATH:-$GOPATH/pebble}
if [[ ! -d ${PEBBLEPATH} ]]; then
  git clone --depth=1 https://github.com/letsencrypt/pebble ${PEBBLEPATH}
fi

cd ${PEBBLEPATH}

docker-compose up -d

set +x  # reduce verbosity while waiting for pebble
for n in `seq 1 150` ; do
  if curl -k https://localhost:14000/dir 2>/dev/null; then
    break
  else
    sleep 1
  fi
done

if ! curl -k https://localhost:14000/dir 2>/dev/null; then
  echo "timed out waiting for pebble to start"
  exit 1
fi

# Setup the DNS resolution used by pebble instance to docker host
curl -X POST -d '{"ip":"10.30.50.1"}' http://localhost:8055/set-default-ipv4
