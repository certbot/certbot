#!/bin/sh

# Tested with: Centos 7 on AWS EC2 t2.micro (x64)

yum install -y \
  git \
  python \
  python-devel \
  python-virtualenv \
  python-devel \
  gcc \
  swig \
  dialog \
  augeas-libs \
  openssl-devel \
  libffi-devel \
  ca-certificates \
  python-setuptools \
  readline-devel
