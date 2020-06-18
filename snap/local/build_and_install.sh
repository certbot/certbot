#!/bin/bash
# Cross-compile the Certbot snap from local sources for the specified architecture,
# and install it if this architecture is also the the current machine one.
# This script is designed for CI tests purpose.
# Usage: build_and_install.sh [amd64,arm64,armhf]
set -ex

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

tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt \
  | grep -v python-augeas > snap-constraints.txt

pushd "${DIR}/packages"
"${CERTBOT_DIR}/tools/simple_http_server.py" 8080 >/dev/null 2>&1 &
HTTP_SERVER_PID="$!"
popd

function cleanup() {
    kill "${HTTP_SERVER_PID}"
}

trap cleanup EXIT

docker run \
  --rm \
  --net=host \
  -v "${CERTBOT_DIR}:/certbot" \
  -w "/certbot" \
  -e "PIP_EXTRA_INDEX_URL=http://localhost:8080" \
  "adferrand/snapcraft:${DOCKER_ARCH}-stable" \
  snapcraft

if [[ "$(arch)" == "${QEMU_ARCH}" ]]; then
    sudo snap install --dangerous --classic *.snap
fi
