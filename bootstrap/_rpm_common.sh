#!/bin/sh

# Tested with:
#   - Fedora 22 (x64)
#   - Centos 7 (x64: on AWS EC2 t2.micro, DigitalOcean droplet)

if type dnf 2>/dev/null
then
  tool=dnf
elif type yum 2>/dev/null
then
  tool=yum
else
  echo "Neither yum nor dnf found. Aborting bootstrap!"
  exit 1
fi

# "git-core" seems to be an alias for "git" in CentOS 7 (yum search fails)
DEPS="git-core
    python
    python-devel
    python-virtualenv
    gcc
    dialog
    augeas-libs
    openssl-devel
    libffi-devel
    ca-certificates "

# Amazon Linux 2015.03 needs python27-virtualenv rather than python-virtualenv
if grep -iq "Amazon Linux" /etc/issue ; then
    DEPS+=python27-virtualenv
fi

$tool install -y $DEPS
