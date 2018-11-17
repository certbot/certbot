#!/bin/bash

cleanup_and_exit() {
    EXIT_STATUS=$?
    unset SERVER
    exit $EXIT_STATUS
}

trap cleanup_and_exit EXIT

export SERVER=https://localhost:14000/dir

./tests/certbot-boulder-integration.sh