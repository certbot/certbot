#!/bin/bash
# Download and run Boulder instance for integration testing
set -xe

# Clone Boulder into a GOPATH-style directory structure even if Go isn't
# installed, because Boulder's docker-compose.yml file wll look for it there.
export GOPATH=${GOPATH:-$HOME/gopath}
BOULDERPATH=${BOULDERPATH:-$GOPATH/src/github.com/letsencrypt/boulder}
if [ ! -d ${BOULDERPATH} ]; then
  git clone --depth=1 https://github.com/letsencrypt/boulder ${BOULDERPATH}
fi

cd ${BOULDERPATH}

docker-compose up -d boulder

set +x  # reduce verbosity while waiting for boulder
for n in `seq 1 150` ; do
  if curl http://localhost:4000/directory 2>/dev/null; then
    break
  else
    sleep 1
  fi
done

if ! curl http://localhost:4000/directory 2>/dev/null; then
  echo "timed out waiting for boulder to start"
  exit 1
fi

# Setup the DNS resolution used by boulder instance to docker host
curl -X POST -d '{"ip":"10.77.77.1"}' http://localhost:8055/set-default-ipv4
