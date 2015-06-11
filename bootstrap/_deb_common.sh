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


# virtualenv binary can be found in different packages depending on
# distro version (#346)
newer () {
  distro=$(lsb_release -si)
  # 6.0.10 => 60, 14.04 => 1404
  # TODO: in sid version==unstable
  version=$(lsb_release -sr | awk -F '.' '{print $1 $2}')
  if [ "$distro" = "Ubuntu" -a "$version" -ge 1410 ]
  then
    return 0;
  elif [ "$distro" = "Debian" -a "$version" -ge 80 ]
  then
    return 0;
  else
    return 1;
  fi
}

# you can force newer if lsb_release is not available (e.g. Docker
# debian:jessie base image)
if [ "$1" = "newer" ] || newer
then
  virtualenv="virtualenv"
else
  virtualenv="python-virtualenv"
fi


# dpkg-dev: dpkg-architecture binary necessary to compile M2Crypto, c.f.
#           #276, https://github.com/martinpaljak/M2Crypto/issues/62,
#           M2Crypto setup.py:add_multiarch_paths

apt-get update
apt-get install -y --no-install-recommends \
  python \
  python-setuptools \
  "$virtualenv" \
  python-dev \
  gcc \
  swig \
  dialog \
  libaugeas0 \
  libssl-dev \
  libffi-dev \
  ca-certificates \
  dpkg-dev \
