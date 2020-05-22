#!/bin/bash
set -emx

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

source "${DIR}/builder/common.sh"

"${DIR}/builder/prepare.sh" "${SNAP_ARCH}"

docker run --net=host -d --rm -v "${DIR}/packages:/data/packages" --name pypiserver pypiserver/pypiserver
tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt > snap-constraints.txt

function cleanup() {
    docker rm --force pypiserver
}

trap cleanup EXIT

docker run \
  --rm \
  --net=host \
  -v "$(pwd):$(pwd)" \
  -w "$(pwd)" \
  -e "PIP_EXTRA_INDEX_URL=http://localhost:8080/simple" \
  -t "builder:${SNAP_ARCH}" \
  snapcraft

if [[ "$(arch)" == "$(GetQemuArch "${SNAP_ARCH}")" ]]; then
    sudo snap install --dangerous --classic *.snap
fi
