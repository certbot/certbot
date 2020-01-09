#!/bin/bash
set -ex

python3 -m venv venv
venv/bin/python -m pip install -e certbot/certbot-ci
venv/bin/python -m pytest certbot/certbot-ci/certbot_integration_tests -n 4

# DO NOT RUN `apache-conf-test` LOCALLY, IT WILL BREAK YOUR APACHE CONFIGURATION!
if [ -n "$TRAVIS" ]; then
    venv/bin/python certbot/certbot-apache/tests/apache-conf-files/apache-conf-test-pebble.py --debian-modules
fi
