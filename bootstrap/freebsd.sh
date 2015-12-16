#!/usr/bin/env sh

set -o errexit
set -o xtrace

pkg install -Ay \
  git \
  python \
  py27-virtualenv \
  augeas \
  libffi \
