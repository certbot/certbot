#!/bin/sh

# Tested with:
#   - 12.04 (x64, Travis)
#   - 14.04 (x64, Vagrant)
#   - 14.10 (x64)

# dpkg-dev: dpkg-architecture binary necessary to compile M2Crypto, c.f.
#           #276, https://github.com/martinpaljak/M2Crypto/issues/62,
#           M2Crypto setup.py:add_multiarch_paths

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
     python python-setuptools python-virtualenv python-dev gcc swig \
     dialog libaugeas0 libssl-dev libffi-dev ca-certificates dpkg-dev
