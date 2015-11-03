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

apt-get install -y --no-install-recommends \
  git \
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
