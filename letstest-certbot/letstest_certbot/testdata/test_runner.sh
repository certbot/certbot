#!/bin/sh -xe
#
# Sets up and runs an integration test.
REPO_DEST="~"
cp -r $CERTBOT_REPO_PATH $REPO_DEST
cd $REPO_DEST
exec "$LETSTEST_TESTDATA_PATH/scripts/$LETSTEST_SCRIPT"
