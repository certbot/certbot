#!/bin/bash -x
XDG_DATA_HOME=${XDG_DATA_HOME:-~/.local/share}
VENV_NAME="venv"
# The path to the letsencrypt-auto script.  Everything that uses these might
# at some point be inlined...
LEA_PATH=./letsencrypt/
VENV_PATH=${LEA_PATH/$VENV_NAME}
VENV_BIN=${VENV_PATH}/bin
BOOTSTRAP=${LEA_PATH}/bootstrap

SUDO=sudo

ExperimentalBootstrap() {
  # Arguments: Platform name, boostrap script name, SUDO command (iff needed)
    if [ "$2" != "" ]  ; then
      echo "Bootstrapping dependencies for $1..."
      if [ "$3" != "" ] ; then
        "$3" "$BOOTSTRAP/$2"
      else
        "$BOOTSTRAP/$2"
      fi
    fi
}

# virtualenv call is not idempotent: it overwrites pip upgraded in
# later steps, causing "ImportError: cannot import name unpack_url"
if [ ! -f $BOOTSTRAP/debian.sh ] ; then
  echo "Cannot find the letsencrypt bootstrap scripts in $BOOTSTRAP"
  exit 1
fi

if [ -f /etc/debian_version ] ; then
  echo "Bootstrapping dependencies for Debian-based OSes..."
  $SUDO $BOOTSTRAP/_deb_common.sh
elif [ -f /etc/redhat-release ] ; then
  echo "Bootstrapping dependencies for RedHat-based OSes..."
  $SUDO $BOOTSTRAP/_rpm_common.sh
elif `grep -q openSUSE /etc/os-release` ; then
  echo "Bootstrapping dependencies for openSUSE-based OSes..."
  $SUDO $BOOTSTRAP/_suse_common.sh
elif [ -f /etc/arch-release ] ; then
  if [ "$DEBUG" = 1 ] ; then
    echo "Bootstrapping dependencies for Archlinux..."
    $SUDO $BOOTSTRAP/archlinux.sh
  else
    echo "Please use pacman to install letsencrypt packages:"
    echo "# pacman -S letsencrypt letsencrypt-apache"
    echo
    echo "If you would like to use the virtualenv way, please run the script again with the"
    echo "--debug flag."
    exit 1
  fi
elif [ -f /etc/manjaro-release ] ; then
  ExperimentalBootstrap "Manjaro Linux" manjaro.sh "$SUDO"
elif [ -f /etc/gentoo-release ] ; then
  ExperimentalBootstrap "Gentoo" _gentoo_common.sh "$SUDO"
elif uname | grep -iq FreeBSD ; then
  ExperimentalBootstrap "FreeBSD" freebsd.sh "$SUDO"
elif uname | grep -iq Darwin ; then
  ExperimentalBootstrap "Mac OS X" mac.sh # homebrew doesn't normally run as root
elif grep -iq "Amazon Linux" /etc/issue ; then
  ExperimentalBootstrap "Amazon Linux" _rpm_common.sh "$SUDO"
else
  echo "Sorry, I don't know how to bootstrap Let's Encrypt on your operating system!"
  echo
  echo "You will need to bootstrap, configure virtualenv, and run a pip install manually"
  echo "Please see https://letsencrypt.readthedocs.org/en/latest/contributing.html#prerequisites"
  echo "for more info"
fi
echo "Bootstrapped!"

cd letsencrypt
./bootstrap/dev/venv.sh
PYVER=`python --version 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//'`

if [ $PYVER -eq 26 ] ; then
    venv/bin/tox -e py26
else
    venv/bin/tox -e py27
fi
