#!/bin/sh

# Tested with:
#   - 12.04 (x64, Travis)
#   - 14.04 (x64, Vagrant)
#   - 14.10 (x64)

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

# dpkg-dev: dpkg-architecture binary necessary to compile M2Crypto, c.f.
#           #276, https://github.com/martinpaljak/M2Crypto/issues/62,
#           M2Crypto setup.py:add_multiarch_paths

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
     python python-setuptools "$virtualenv" python-dev gcc swig \
     dialog libaugeas0 libssl-dev libffi-dev ca-certificates dpkg-dev
