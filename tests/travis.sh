#!/bin/bash

set -o errexit

if [ -n "${BOULDER_INTEGRATION+x}" ]; then
    ./tests/boulder-fetch.sh
fi

travis_retry tox

if [ -n "${BOULDER_INTEGRATION+x}" ]; then
    source .tox/$TOXENV/bin/activate

    until curl http://boulder:4000/directory 2>/dev/null; do
      echo waiting for boulder
      sleep 1
    done

    ./tests/boulder-integration.sh
fi
