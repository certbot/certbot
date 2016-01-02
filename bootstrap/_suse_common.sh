#!/bin/sh

# SLE12 don't have python-virtualenv

zypper -nq in -l \
  python \
  python-devel \
  python-virtualenv \
  gcc \
  dialog \
  augeas-lenses \
  libopenssl-devel \
  libffi-devel \
  ca-certificates \
