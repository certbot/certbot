#!/bin/bash
set -ex

SNAP_ARCHS=$1

if [[ -z "${SNAP_ARCHS}" ]]; then
    echo "You need to specify at least one target architecture"
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CERTBOT_DIR="$(dirname "$(dirname "${DIR}")")"

trap popd EXIT

pushd "${CERTBOT_DIR}"
snapcraft remote-build --launchpad-accept-public-upload --build-on="${SNAP_ARCHS}"
popd
