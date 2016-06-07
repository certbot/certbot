#!/bin/sh -xe
# Developer Python3 virtualenv setup for Certbot

export VENV_NAME="${VENV_NAME:-venv3}"
export VENV_ARGS="--python python3"

./tools/_venv_common.sh \
  -e acme[dev] \
