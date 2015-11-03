#!/bin/sh -e
#
# Install OS dependencies.  In the glorious future, letsencrypt-auto will
# source this...

if test "`id -u`" -ne "0" ; then
  SUDO=sudo
else
  SUDO=
fi

BOOTSTRAP=`dirname $0`
if [ ! -f $BOOTSTRAP/debian.sh ] ; then
  echo "Cannot find the letsencrypt bootstrap scripts in $BOOTSTRAP"
  exit 1
fi
if [ -f /etc/debian_version ] ; then
  echo "Bootstrapping dependencies for Debian-based OSes..."
  $SUDO $BOOTSTRAP/_deb_common.sh
elif [ -f /etc/arch-release ] ; then
  echo "Bootstrapping dependencies for Archlinux..."
  $SUDO $BOOTSTRAP/archlinux.sh
elif [ -f /etc/redhat-release ] ; then
  echo "Bootstrapping dependencies for RedHat-based OSes..."
  $SUDO $BOOTSTRAP/_rpm_common.sh
elif [ -f /etc/gentoo-release ] ; then
  echo "Bootstrapping dependencies for Gentoo-based OSes..."
  $SUDO $BOOTSTRAP/_gentoo_common.sh
elif uname | grep -iq FreeBSD ; then
  echo "Bootstrapping dependencies for FreeBSD..."
  $SUDO $BOOTSTRAP/freebsd.sh
elif uname | grep -iq Darwin ; then
  echo "Bootstrapping dependencies for Mac OS X..."
  echo "WARNING: Mac support is very experimental at present..."
  $BOOTSTRAP/mac.sh
else
  echo "Sorry, I don't know how to bootstrap Let's Encrypt on your operating system!"
  echo
  echo "You will need to bootstrap, configure virtualenv, and run a pip install manually"
  echo "Please see https://letsencrypt.readthedocs.org/en/latest/contributing.html#prerequisites"
  echo "for more info"
  exit 1
fi
