#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source "${DIR}/common.sh"

SNAP_ARCH=$1
TARGET_ARCH=$(GetDockerArch "${SNAP_ARCH}")
QEMU_ARCH=$(GetQemuArch "${SNAP_ARCH}")

RegisterQemuHandlers
echo "QEMU_ARCH is ${QEMU_ARCH}"
DownloadQemuStatic "${QEMU_ARCH}"

docker build --network=host --build-arg "SNAP_ARCH=${SNAP_ARCH}" --build-arg "TARGET_ARCH=${TARGET_ARCH}" --build-arg "QEMU_ARCH=${QEMU_ARCH}" -t "builder:${SNAP_ARCH}" "${DIR}"
