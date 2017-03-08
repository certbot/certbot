#!/bin/sh -xe
# Developer virtualenv setup for Certbot client

if command -v python2; then
    export VENV_ARGS="--python python2"
elif command -v python2.7; then
    export VENV_ARGS="--python python2.7"
else
    echo "Couldn't find python2 or python2.7 in $PATH"
    exit 1
fi

./tools/_venv_common.sh \
  -e acme[dev] \
  -e .[dev,docs] \
  -e certbot-apache \
  -e certbot-nginx \
  -e letshelp-certbot \
  -e certbot-compatibility-test
