#!/bin/sh -xe
# Developer Python3 virtualenv setup for Certbot

if command -v python3; then
    export VENV_NAME="${VENV_NAME:-venv3}"
    export VENV_ARGS="--python python3"
else
    echo "Couldn't find python3 in $PATH"
    exit 1
fi

./tools/_venv_common.sh \
  -e acme[dev] \
  -e .[dev,docs] \
  -e certbot-apache \
  -e certbot-nginx \
  -e letshelp-certbot \
  -e certbot-compatibility-test
