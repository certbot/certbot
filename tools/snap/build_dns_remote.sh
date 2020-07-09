#!/bin/bash
set -ex

DNS_PLUGINS=$1
SNAP_ARCHS=$2

if [[ -z "${DNS_PLUGINS}" ]]; then
    echo "You need to specify the DNS plugins"
    exit 1
fi

if [[ -z "${SNAP_ARCHS}" ]]; then
    echo "You need to specify at least one target architecture"
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CERTBOT_DIR="$(dirname "$(dirname "${DIR}")")"

trap popd EXIT

IFS=","
for DNS_PLUGIN in ${DNS_PLUGINS}; do
    pushd "${CERTBOT_DIR}/${DNS_PLUGIN}"
    python3 ../tools/strip_hashes.py ../letsencrypt-auto-source/pieces/dependency-requirements.txt | grep -v python-augeas > snap-constraints.txt
    snapcraft remote-build --launchpad-accept-public-upload --build-on="${SNAP_ARCHS}"
    popd
done
