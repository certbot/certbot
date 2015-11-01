#!/bin/sh -xe
# Developer Python3 virtualenv setup for Let's Encrypt

export VENV_NAME="${VENV_NAME:-venv3}"
export VENV_ARGS="--python python3"

./bootstrap/dev/_venv_common.sh \
  -e acme[testing] \
