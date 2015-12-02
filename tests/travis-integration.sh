#!/bin/bash

set -o errexit

./tests/boulder-fetch.sh

source .tox/$TOXENV/bin/activate

export LETSENCRYPT_PATH=`pwd`

cd $GOPATH/src/github.com/letsencrypt/boulder/

# boulder's integration-test.py has code that knows to start and wait for the
# boulder processes to start reliably and then will run the letsencrypt
# boulder-interation.sh on its own. The --letsencrypt flag says to run only the
# letsencrypt tests (instead of any other client tests it might run). We're
# going to want to define a more robust interaction point between the boulder
# and letsencrypt tests, but that will be better built off of this.
python test/integration-test.py --letsencrypt
