#!/bin/bash
set -ex

SNAP_ARCHS=$1
DNS_PLUGINS=$2

if [[ -z "${SNAP_ARCHS}" ]]; then
    echo "You need to specify at least one target architecture"
    exit 1
fi

if [[ -z "${DNS_PLUGINS}" ]]; then
    echo "You need to specify the DNS plugins"
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CERTBOT_DIR="$(dirname "$(dirname "${DIR}")")"

if [[ "${DNS_PLUGINS}" = "ALL" ]]; then
    DNS_PLUGINS=$(find ${CERTBOT_DIR} -maxdepth 1 -type d -name "certbot-dns-*" -exec basename {} \; | paste -sd "," -)
fi

trap popd EXIT

function run() {
    local DNS_PLUGIN=$1
    pushd "${CERTBOT_DIR}/${DNS_PLUGIN}"
    python3 ../tools/strip_hashes.py ../letsencrypt-auto-source/pieces/dependency-requirements.txt | grep -v python-augeas > snap-constraints.txt
    snapcraft remote-build --launchpad-accept-public-upload --build-on="${SNAP_ARCHS}"
    popd
}

IFS=","
for DNS_PLUGIN in ${DNS_PLUGINS}; do
    run "${DNS_PLUGIN}" &
done

wait
