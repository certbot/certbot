#!/bin/sh -xe
# Developer virtualenv setup for Let's Encrypt client

export VENV_ARGS="--python python2"

./tools/_venv_common.sh \
  -e acme[dev] \
  -e .[dev,docs] \
  -e letsencrypt-apache \
  -e letsencrypt-nginx \
  -e letshelp-letsencrypt \
  -e letsencrypt-compatibility-test
