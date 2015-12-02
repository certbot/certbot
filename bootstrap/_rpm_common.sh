#!/bin/sh

# Tested with:
#   - Fedora 22, 23 (x64)
#   - Centos 7 (x64: onD igitalOcean droplet)

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

# Some distros and older versions of current distros use a "python27"
# instead of "python" naming convention. Try both conventions.
if ! $tool install -y \
       python \
       python-devel \
       python-virtualenv
then
  if ! $tool install -y \
         python27 \
         python27-devel \
         python27-virtualenv
  then
    echo "Could not install Python dependencies. Aborting bootstrap!"
    exit 1
  fi
fi

# "git-core" seems to be an alias for "git" in CentOS 7 (yum search fails)
if ! $tool install -y \
       git-core \
       gcc \
       dialog \
       augeas-libs \
       openssl-devel \
       libffi-devel \
       redhat-rpm-config \
       ca-certificates
then
    echo "Could not install additional dependencies. Aborting bootstrap!"
    exit 1
fi
