#!/bin/sh
pep8 \
  setup.py \
  acme \
  letsencrypt \
  letsencrypt-apache \
  letsencrypt-nginx \
  letsencrypt-compatibility-test \
  letshelp-letsencrypt \
  letsencrypt-plesk \
  || echo "PEP8 checking failed, but it's ignored in Travis"

# echo exits with 0
