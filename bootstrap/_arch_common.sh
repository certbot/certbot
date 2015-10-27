#!/bin/sh

# Tested with:
#   - Manjaro 15.09 (x86_64)
#   - ArchLinux (x86_64)

# Both "gcc-multilib" and "gcc" packages provide gcc. If user already has
# "gcc-multilib" installed, let's stick to their choice
if pacman -Qc gcc-multilib &>/dev/null
then
	GCC_PACKAGE="gcc-multilib";
else
	GCC_PACKAGE="gcc";
fi

# "python-virtualenv" is Python3, but "python2-virtualenv" provides
# only "virtualenv2" binary, not "virtualenv" necessary in
# ./bootstrap/dev/_common_venv.sh
pacman -S --needed \
  git \
  python2 \
  python-virtualenv \
  "$GCC_PACKAGE" \
  dialog \
  augeas \
  openssl \
  libffi \
  ca-certificates \
  pkg-config \
