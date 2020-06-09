#!/bin/bash
# Cross-compile the Certbot snap from local sources for the specified architecture,
# and install it if this architecture is also the the current machine one.
# This script is designed for CI tests purpose.
# Usage: build_and_install.sh [amd64,arm64,armhf]
set -ex

if [[ -z "${TRAVIS}" ]]; then
    echo "This script makes global changes to the system it is run on so should only be run in CI."
    exit 1
fi

SNAP_ARCH=$1

if [[ -z "${SNAP_ARCH}" ]]; then
    echo "You need to specify the target architecture"
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CERTBOT_DIR="$(dirname "$(dirname "${DIR}")")"

# shellcheck source=common.sh
source "${DIR}/common.sh"

RegisterQemuHandlers
ResolveArch "${SNAP_ARCH}"

docker run --net=host -d --rm -v "${DIR}/packages:/data/packages" --name pypiserver pypiserver/pypiserver
tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt > snap-constraints.txt

function cleanup() {
    docker rm --force pypiserver
}

trap cleanup EXIT

docker run \
  --rm \
  --net=host \
  -v "${CERTBOT_DIR}:/certbot" \
  -w "/certbot" \
  -e "PIP_EXTRA_INDEX_URL=http://localhost:8080/simple" \
  "adferrand/snapcraft:${DOCKER_ARCH}-stable" \
  snapcraft

if [[ "$(arch)" == "${QEMU_ARCH}" ]]; then
    sudo snap install --dangerous --classic *.snap
fi
