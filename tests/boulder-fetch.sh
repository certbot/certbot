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
FAKE_DNS=$(ifconfig docker0 | grep "inet addr:" | cut -d: -f2 | awk '{ print $1}')
[ -z "$FAKE_DNS" ] && FAKE_DNS=$(ifconfig docker0 | grep "inet " | xargs | cut -d ' ' -f 2)
[ -z "$FAKE_DNS" ] && FAKE_DNS=$(ip addr show dev docker0 | grep "inet " | xargs | cut -d ' ' -f 2 | cut -d '/' -f 1)
[ -z "$FAKE_DNS" ] && echo Unable to find the IP for docker0 && exit 1
sed -i "s/FAKE_DNS: .*/FAKE_DNS: ${FAKE_DNS}/" docker-compose.yml

# If we're testing against ACMEv2, we need to use a newer boulder config for
# now. See https://github.com/letsencrypt/boulder#quickstart.
if [ "$BOULDER_INTEGRATION" = "v2" ]; then
    sed -i 's/BOULDER_CONFIG_DIR: .*/BOULDER_CONFIG_DIR: test\/config-next/' docker-compose.yml
fi

docker-compose up -d
printf "\n10.77.77.77 boulder" | sudo tee -a /etc/hosts

set +x  # reduce verbosity while waiting for boulder
for n in `seq 1 300` ; do
  if curl -v http://boulder:4000/directory ; then
    break
  else
    echo waiting for boulder
    sleep 1
  fi
  if [[ $n == 300 ]]; then
    echo timed out waiting for boulder
    exit 1
  fi
done
