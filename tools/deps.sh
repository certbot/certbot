#!/bin/sh
#
# Find all Python imports.
#
#  ./deps.sh letsencrypt
#  ./deps.sh acme
#  ./deps.sh letsencrypt-apache
#  ...
#
# Manually compare the output with deps in setup.py.

git grep -h -E '^(import|from.*import)' $1/ | \
    awk '{print $2}' | \
    grep -vE "^$1" | \
    sort -u
