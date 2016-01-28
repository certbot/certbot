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
if apt-cache show virtualenv > /dev/null 2>&1; then
  virtualenv="virtualenv"
fi

if apt-cache show python-virtualenv > /dev/null 2>&1; then
  virtualenv="$virtualenv python-virtualenv"
fi

augeas_pkg="libaugeas0 augeas-lenses"
AUGVERSION=`apt-cache show --no-all-versions libaugeas0 | grep ^Version: | cut -d" " -f2`

AddBackportRepo() {
    # ARGS:
    BACKPORT_NAME="$1"
    BACKPORT_SOURCELINE="$2"
    if ! grep -v -e ' *#' /etc/apt/sources.list | grep -q "$BACKPORT_NAME" ; then
        # This can theoretically error if sources.list.d is empty, but in that case we don't care.
        if ! grep -v -e ' *#' /etc/apt/sources.list.d/* 2>/dev/null | grep -q "$BACKPORT_NAME"; then
            /bin/echo -n "Installing augeas from $BACKPORT_NAME in 3 seconds..."
            sleep 1s
            /bin/echo -ne "\e[0K\rInstalling augeas from $BACKPORT_NAME in 2 seconds..."
            sleep 1s
            /bin/echo -e "\e[0K\rInstalling augeas from $BACKPORT_NAME in 1 second ..."
            sleep 1s
            if echo $BACKPORT_NAME | grep -q wheezy ; then
                /bin/echo '(Backports are only installed if explicitly requested via "apt-get install -t wheezy-backports")'
            fi

            echo $BACKPORT_SOURCELINE >> /etc/apt/sources.list.d/"$BACKPORT_NAME".list
            apt-get update
        fi
    fi
    apt-get install -y --no-install-recommends -t "$BACKPORT_NAME" $augeas_pkg
    augeas_pkg=

}


if dpkg --compare-versions 1.0 gt "$AUGVERSION" ; then
    if lsb_release -a | grep -q wheezy ; then
        AddBackportRepo wheezy-backports "deb http://http.debian.net/debian wheezy-backports main"
    elif lsb_release -a | grep -q precise ; then
        # XXX add ARM case
        AddBackportRepo precise-backports "deb http://archive.ubuntu.com/ubuntu precise-backports main restricted universe multiverse"
    else
        echo "No libaugeas0 version is available that's new enough to run the"
        echo "Let's Encrypt apache plugin..."
    fi
    # XXX add a case for ubuntu PPAs
fi

apt-get install -y --no-install-recommends \
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
