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

apt-get update

# dpkg-dev: dpkg-architecture binary necessary to compile M2Crypto, c.f.
#           #276, https://github.com/martinpaljak/M2Crypto/issues/62,
#           M2Crypto setup.py:add_multiarch_paths

common_packages="python python-setuptools python-dev gcc swig dialog libaugeas0 libssl-dev openssl libffi-dev dpkg-dev ca-certificates"

if [ "$1" = "no_venv" ]
then
  packages="$common_packages"
else

  # virtualenv binary can be found in different packages depending on
  # distro version (#346)
  distro=$(lsb_release -si)
  # 6.0.10 => 60, 14.04 => 1404
  version=$(lsb_release -sr | awk -F '.' '{print $1 $2}')
  if [ "$distro" = "Ubuntu" -a "$version" -ge 1410 ]
  then
    virtualenv="virtualenv"
  elif [ "$distro" = "Debian" -a "$version" -ge 80 ]
  then
    virtualenv="virtualenv"
  else
    virtualenv="python-virtualenv"
  fi

  packages="$virtualenv $common_packages"
fi

apt-get install -y --no-install-recommends $packages
