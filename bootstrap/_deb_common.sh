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

augeas_pkg=libaugeas0
AUGVERSION=`apt-cache show --no-all-versions libaugeas0 | grep ^Version: | cut -d" " -f2`

if dpkg --compare-version 1.0 gt "$AUGVERSION" ; then
    if lsb_release -a | grep -q wheezy ; then
        if ! grep -v -e ' *#' /etc/apt/sources.list | grep -q wheezy-backports ; then
            # XXX ask for permission before doing this?
            echo Installing augeas from wheezy-backports...
            echo deb http://http.debian.net/debian wheezy-backports main >> /etc/apt/sources.list
            apt-get update
            apt-get install -y --no-install-recommends -t wheezy-backports libaugeas0
        fi
        augeas_pkg=
    else
        echo "No libaugeas0 version is available that's new enough to run the"
        echo "Let's Encrypt apache plugin..."
    fi
    # XXX add a case for ubuntu PPAs
fi

apt-get install -y --no-install-recommends \
  git \
  python \
  python-dev \
  $virtualenv \
  gcc \
  dialog \
  $augeas_pkg \
  libssl-dev \
  libffi-dev \
  ca-certificates \



if ! command -v virtualenv > /dev/null ; then
  echo Failed to install a working \"virtualenv\" command, exiting
  exit 1
fi
