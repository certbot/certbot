#!/bin/bash
# Download and run Pebble instance for integration testing
set -xe

PEBBLE_VERSION=2018-11-02

# We reuse the same GOPATH-style directory than for Boulder.
# Pebble does not need it, but it will make the installation consistent with Boulder's one.
export GOPATH=${GOPATH:-$HOME/gopath}
PEBBLEPATH=${PEBBLEPATH:-$GOPATH/src/github.com/letsencrypt/pebble}

mkdir -p ${PEBBLEPATH}

cat << UNLIKELY_EOF > "$PEBBLEPATH/docker-compose.yml"
version: '3'

services:
 pebble:
  image: letsencrypt/pebble:${PEBBLE_VERSION}
  command: pebble -strict ${PEBBLE_STRICT:-false} -dnsserver 10.77.77.1
  ports:
    - 14000:14000
  environment:
    - PEBBLE_VA_NOSLEEP=1
UNLIKELY_EOF

docker-compose -f "$PEBBLEPATH/docker-compose.yml" up -d pebble

set +x  # reduce verbosity while waiting for boulder
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
