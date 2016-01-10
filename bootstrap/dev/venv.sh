#!/bin/sh -xe
# Developer virtualenv setup for Let's Encrypt client

export VENV_ARGS="--python python2"

./bootstrap/dev/_venv_common.sh \
  -e acme[testing] \
  -e .[dev,docs,testing] \
  -e letsencrypt-apache \
  -e letsencrypt-nginx \
  -e letshelp-letsencrypt \
  -e letsencrypt-compatibility-test
