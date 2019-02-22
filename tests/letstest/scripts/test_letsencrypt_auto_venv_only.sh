#!/bin/bash -x

# $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL are dynamically set at execution

cd letsencrypt
# help installs virtualenv and does nothing else
./letsencrypt-auto-source/letsencrypt-auto -v --debug --help all
