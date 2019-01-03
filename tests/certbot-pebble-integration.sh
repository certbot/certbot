#!/bin/bash
# Simple integration test. Make sure to activate virtualenv beforehand
# (source venv/bin/activate) and that you are running Pebble test
# instance (see ./pebble-fetch.sh).

cleanup_and_exit() {
    EXIT_STATUS=$?
    unset SERVER
    exit $EXIT_STATUS
}

trap cleanup_and_exit EXIT

export SERVER=https://localhost:14000/dir

./tests/certbot-boulder-integration.sh
