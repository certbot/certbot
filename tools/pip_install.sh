#!/bin/bash -e
# pip installs packages using pinned package versions. If CERTBOT_OLDEST is set
# to 1, a combination of tools/oldest_constraints.txt,
# tools/dev_constraints.txt, and local-oldest-requirements.txt contained in the
# top level of the package's directory is used, otherwise, a combination of
# certbot-auto's requirements file and tools/dev_constraints.txt is used. The
# other file always takes precedence over tools/dev_constraints.txt. If
# CERTBOT_OLDEST is set, this script must be run with `-e <package-name>` and
# no other arguments.

# get the root of the Certbot repo
tools_dir=$(dirname $("$(dirname $0)/readlink.py" $0))
all_constraints=$(mktemp)
test_constraints=$(mktemp)
trap "rm -f $all_constraints $test_constraints" EXIT

if [ "$CERTBOT_OLDEST" = 1 ]; then
    if [ "$1" != "-e" -o "$#" -ne "2" ]; then
        echo "When CERTBOT_OLDEST is set, this script must be run with a single -e <path> argument."
        exit 1
    fi
    pkg_dir=$(echo $2 | cut -f1 -d\[)  # remove any extras such as [dev]
    requirements="$pkg_dir/local-oldest-requirements.txt"
    # packages like acme don't have any local oldest requirements
    if [ ! -f "$requirements" ]; then
        unset requirements
    fi
    cp "$tools_dir/oldest_constraints.txt" "$test_constraints"
else
    repo_root=$(dirname "$tools_dir")
    certbot_requirements="$repo_root/letsencrypt-auto-source/pieces/dependency-requirements.txt"
    sed -n -e 's/^\([^[:space:]]*==[^[:space:]]*\).*$/\1/p' "$certbot_requirements" > "$test_constraints"
fi

"$tools_dir/merge_requirements.py" "$tools_dir/dev_constraints.txt" \
                                   "$test_constraints" > "$all_constraints"

set -x

# install the requested packages using the pinned requirements as constraints
if [ -n "$requirements" ]; then
    pip install -q --constraint "$all_constraints" --requirement "$requirements"
fi
pip install -q --constraint "$all_constraints" "$@"
