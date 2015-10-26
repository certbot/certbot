#!/bin/sh

# Tested with:
#   - Manjaro 15.09 (x86_64)
#   - ArchLinux (x86_64)

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
