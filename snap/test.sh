#!/bin/bash
set -ex

cd certbot

python3 -m venv venv
. venv/bin/activate
pip install -e certbot-ci

pytest certbot-ci/certbot_integration_tests/certbot_tests --numprocesses 4 --acme-server=pebble 
