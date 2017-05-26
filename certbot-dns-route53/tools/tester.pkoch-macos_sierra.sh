#!/bin/bash
# I just wanted a place to dump the incantations I use for testing.
set -e

brew install openssl libffi

rm -rf scratch; mkdir scratch

virtualenv scratch/venv -p /usr/local/bin/python2.7
scratch/venv/bin/pip install -U pip setuptools

CPPFLAGS=-I/usr/local/opt/openssl/include LDFLAGS=-L/usr/local/opt/openssl/lib scratch/venv/bin/pip install -e .

scratch/venv/bin/certbot certonly -n --agree-tos --test-cert --email pkoch@lifeonmars.pt -a certbot-route53:auth -d pkoch.lifeonmars.pt --work-dir scratch --config-dir scratch --logs-dir scratch

rm -rf scratch
