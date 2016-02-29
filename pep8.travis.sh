#!/bin/sh

set -e  # Fail fast

# PEP8 is not ignored in ACME
pep8 --config=acme/.pep8 acme

pep8 \
  setup.py \
  letsencrypt \
  letsencrypt-apache \
  letsencrypt-nginx \
  letsencrypt-compatibility-test \
  letshelp-letsencrypt \
  || echo "PEP8 checking failed, but it's ignored in Travis"

# echo exits with 0
