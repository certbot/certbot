#!/bin/sh -e
# pip installs packages using Certbot's requirements file as constraints

# get the root of the Certbot repo
repo_root=$(git rev-parse --show-toplevel)
requirements="$repo_root/letsencrypt-auto-source/pieces/dependency-requirements.txt"
constraints=$(mktemp)
trap "rm -f $constraints" EXIT
# extract pinned requirements without hashes
sed -n -e 's/^\([^[:space:]]*==[^[:space:]]*\).*$/\1/p' $requirements > $constraints

# install the requested packages using the pinned requirements as constraints
pip install --constraint $constraints "$@"
