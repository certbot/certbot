#!/bin/sh
#
# Install OS dependencies for test farm tests.
#
# This does not include the dependencies needed to build cryptography. See
# https://cryptography.io/en/latest/installation/#building-cryptography-on-linux

set -ex  # Work even if somebody does "sh thisscript.sh".

error() {
    echo "$@"
}

if [ -f /etc/debian_version ]; then
  sudo apt-get update || error apt-get update hit problems but continuing anyway...

  PYENV_DEPS="make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
              wget curl llvm libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev \
              liblzma-dev git"
  ALL_DEPS="libaugeas-dev $PYENV_DEPS"
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $ALL_DEPS
elif [ -f /etc/redhat-release ]; then
  PYENV_DEPS="gcc zlib-devel bzip2 bzip2-devel readline-devel sqlite sqlite-devel openssl-devel \
              tk-devel libffi-devel xz-devel git"
  ALL_DEPS="augeas-devel $PYENV_DEPS"

  if yum list installed "httpd" >/dev/null 2>&1; then
    ALL_DEPS="mod_ssl $ALL_DEPS"
  fi

  sudo yum install -y $ALL_DEPS
fi
