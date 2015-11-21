#!/bin/sh

# Current version tested with:
#
# - Ubuntu
#     - 14.04 (x64)
#     - 15.04 (x64)
# - Debian
#     - 7.9 "wheezy" (x64)
#     - sid (2015-10-21) (x64)

# Past versions tested with:
#
# - Debian 8.0 "jessie" (x64)
# - Raspbian 7.8 (armhf)

# Believed not to work:
#
# - Debian 6.0.10 "squeeze" (x64)

apt-get update

# virtualenv binary can be found in different packages depending on
# distro version (#346)

virtualenv=
if apt-cache show virtualenv > /dev/null ; then
  virtualenv="virtualenv"
fi

if apt-cache show python-virtualenv > /dev/null ; then
  virtualenv="$virtualenv python-virtualenv"
fi

# This is likely to be unecessary in almost all cases,
# but if python-dev actually depends some non-2.7 version,
# but python2.7 is installed, we'll want this dev package
# https://github.com/letsencrypt/letsencrypt/issues/1564
pydev=python-dev
if apt-cache show python2.7-dev > /dev/null ; then
  pydev="$pydev python2.7-dev"
fi

apt-get install -y --no-install-recommends \
  git \
  python \
  $pydev \
  $virtualenv \
  gcc \
  dialog \
  libaugeas0 \
  libssl-dev \
  libffi-dev \
  ca-certificates \

if ! command -v virtualenv > /dev/null ; then
  echo Failed to install a working \"virtualenv\" command, exiting
  exit 1
fi
