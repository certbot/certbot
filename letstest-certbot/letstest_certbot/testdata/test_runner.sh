#!/bin/sh -xe
#
# Sets up and runs an integration test.
REPO_DEST="~/certbot"
cp -r $LETSTEST_REPO $REPO_DEST
cd $REPO_DEST
exec "$(pwd)/scripts/$LETSTEST_SCRIPT"
