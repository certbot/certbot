#!/bin/sh

# Manjaros package-management is very similiar to Arch-Linux.
# Therefore this script is currently identical to <archlinux.sh>.
# This must not hold in future.

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
