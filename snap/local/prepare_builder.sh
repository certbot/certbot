#!/bin/bash
# Build a snapcraft docker suitable for cross-compilation of snaps on foreign architectures.
set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source "${DIR}/common_libs.sh"

SNAP_ARCH=$1
TARGET_ARCH=$(GetDockerArch "${SNAP_ARCH}")
QEMU_ARCH=$(GetQemuArch "${SNAP_ARCH}")

RegisterQemuHandlers
echo "QEMU_ARCH is ${QEMU_ARCH}"
DownloadQemuStatic "${QEMU_ARCH}" "${DIR}"

docker build \
    --build-arg "SNAP_ARCH=${SNAP_ARCH}" \
    --build-arg "TARGET_ARCH=${TARGET_ARCH}" \
    --build-arg "QEMU_ARCH=${QEMU_ARCH}" \
    -f "${DIR}/builder.Dockerfile" \
    -t "builder:${SNAP_ARCH}" \
    "${DIR}"
