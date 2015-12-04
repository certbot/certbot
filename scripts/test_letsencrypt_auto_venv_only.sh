#!/bin/bash -x

# $BOULDER_URL is dynamically set at execution

cd letsencrypt
# help installs virtualenv and does nothing else
./letsencrypt-auto -v --help all
