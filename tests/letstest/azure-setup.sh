#!/bin/bash -ex
#
# Preps the test farm tests to be run in Travis.

if [ "$BUILD_REASON" = "PullRequest" ]; then
    echo This script must be run in Azure on a non-pull request build
    exit 1
fi

openssl aes-256-cbc -K "${FARMTEST_SECURE_KEY}" -iv "${FARMTEST_SECURE_IV}" -in azure-test-farm.pem.enc -out azure-test-farm.pem -d
