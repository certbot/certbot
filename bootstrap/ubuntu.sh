#!/bin/sh

# Tested with:
#   - 12.04 (Travis)
#   - 14.04 (Vagrant)

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
     python python-setuptools python-virtualenv python-dev gcc swig \
     dialog libaugeas0 libssl-dev libffi-dev ca-certificates
