#!/bin/bash
# Download and run Pebble instance for integration testing
set -xe

PEBBLE_VERSION=v1.0.1

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
    command: pebble -dnsserver 10.30.50.3:8053
    environment:
    - PEBBLE_VA_NOSLEEP=1
    ports:
      - 14000:14000
    networks:
      acmenet:
        ipv4_address: 10.30.50.2
  challtestsrv:
    image: letsencrypt/pebble-challtestsrv:${PEBBLE_VERSION}
    command: pebble-challtestsrv -defaultIPv6 "" -defaultIPv4 10.30.50.1
    ports:
      - 8055:8055
    networks:
      acmenet:
        ipv4_address: 10.30.50.3
networks:
  acmenet:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 10.30.50.0/24
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
