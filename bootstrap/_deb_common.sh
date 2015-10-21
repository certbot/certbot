#!/bin/sh

# Tested with:
#   - Ubuntu:
#     - 12.04 (x64, Travis)
#     - 14.04 (x64, Vagrant)
#     - 14.10 (x64)
#   - Debian:
#     - 6.0.10 "squeeze" (x64)
#     - 7.8 "wheezy" (x64)
#     - 8.0 "jessie" (x64)
#   - Raspbian:
#     - 7.8 (armhf)

apt-get update

# virtualenv binary can be found in different packages depending on
# distro version (#346)

virtualenv=
if apt-cache show virtualenv > /dev/null ; then
  virtualenv="virtualenv"
fi

if apt-cache show python-virtualenv > /dev/null ; then
  virtualenv="$virualenv python-virtualenv"
fi

apt-get install -y --no-install-recommends \
  git-core \
  python \
  python-dev \
  $virtualenv \
  gcc \
  dialog \
  libaugeas0 \
  libssl-dev \
  libffi-dev \
  ca-certificates \

if ! which virtualenv > /dev/null ; then
  echo Failed to install a working \"virtualenv\" command, exiting
  exit 1
fi
