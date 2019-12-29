#!/bin/bash -ex
#
# Preps the test farm tests to be run in Travis.

if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
    echo This script must be run in Travis on a non-pull request build
    exit 1
fi

openssl aes-256-cbc -K "${encrypted_9a387195a62e_key}" -iv "${encrypted_9a387195a62e_iv}" -in travis-test-farm.pem.enc -out travis-test-farm.pem -d
