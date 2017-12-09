#!/bin/sh -e
# pip installs packages using pinned package versions

# get the root of the Certbot repo
my_path=$("$(dirname $0)/readlink.py" $0)
repo_root=$(dirname $(dirname $my_path))
requirements="$repo_root/letsencrypt-auto-source/pieces/dependency-requirements.txt"
certbot_auto_constraints=$(mktemp)
trap "rm -f $certbot_auto_constraints" EXIT
# extract pinned requirements without hashes
sed -n -e 's/^\([^[:space:]]*==[^[:space:]]*\).*$/\1/p' $requirements > $certbot_auto_constraints
dev_constraints="$(dirname $my_path)/pip_constraints.txt"

set -x

# install the requested packages using the pinned requirements as constraints
pip install -q --constraint $certbot_auto_constraints --constraint $dev_constraints "$@"
