#!/bin/sh

# "python-virtualenv" is Python3, but "python2-virtualenv" provides
# only "virtualenv2" binary, not "virtualenv" necessary in
# ./bootstrap/dev/_common_venv.sh
pacman -S --needed \
  git \
  python2 \
  python-virtualenv \
  gcc \
  dialog \
  augeas \
  openssl \
  libffi \
  ca-certificates \
