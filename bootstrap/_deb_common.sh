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

if dpkg --compare-versions 1.0 gt "$AUGVERSION" ; then
    if lsb_release -a | grep -q wheezy ; then
        if ! grep -v -e ' *#' /etc/apt/sources.list | grep -q wheezy-backports ; then
            # This can theoretically error if sources.list.d is empty, but in that case we don't care.
            if ! grep -v -e ' *#' /etc/apt/sources.list.d/* 2>/dev/null | grep -q wheezy-backports ; then
                /bin/echo -n "Installing augeas from wheezy-backports in 3 seconds..."
                sleep 1s
                /bin/echo -ne "\e[0K\rInstalling augeas from wheezy-backports in 2 seconds..."
                sleep 1s
                /bin/echo -e "\e[0K\rInstalling augeas from wheezy-backports in 1 second ..."
                sleep 1s
                /bin/echo '(Backports are only installed if explicitly requested via "apt-get install -t wheezy-backports")'

                echo deb http://http.debian.net/debian wheezy-backports main >> /etc/apt/sources.list.d/wheezy-backports.list
                apt-get update
            fi
        fi
        apt-get install -y --no-install-recommends -t wheezy-backports libaugeas0
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
