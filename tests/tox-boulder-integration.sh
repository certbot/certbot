#!/bin/bash -e
# A simple wrapper around tests/boulder-integration.sh that activates the tox
# virtual environment defined by the environment variable TOXENV before running
# integration tests.

if [ -z "${TOXENV+x}" ]; then
    echo "The environment variable TOXENV must be set to use this script!" >&2
    exit 1
fi

source .tox/$TOXENV/bin/activate
tests/boulder-integration.sh
