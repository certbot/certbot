#!/bin/sh

set -e  # Fail fast

# PEP8 is not ignored in ACME
pep8 --config=acme/.pep8 acme

pep8 \
  setup.py \
  certbot \
  certbot-apache \
  certbot-nginx \
  certbot-compatibility-test \
  letshelp-certbot \
  || echo "PEP8 checking failed, but it's ignored in Travis"

# echo exits with 0
