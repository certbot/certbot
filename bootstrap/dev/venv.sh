#!/bin/sh -xe
# Developer virtualenv setup for Let's Encrypt client

export VENV_ARGS="--python python2"

./bootstrap/dev/_venv_common.sh \
  -r py26reqs.txt \
  -e acme[testing] \
  -e .[dev,docs,testing] \
  -e letsencrypt-apache \
  -e letsencrypt-nginx \
  -e letshelp-letsencrypt \
  -e letsencrypt-compatibility-test

# Workaround for https://github.com/letsencrypt/letsencrypt/issues/1342
# Ensure we are at the top of a letsencrypt developer tree first
if grep -q github.com/letsencrypt/letsencrypt .git/config ; then
  find . -iname '*.pyc' -exec rm -f '{}' ';'
fi
