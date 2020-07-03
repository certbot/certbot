#!/bin/bash
# Common bash functions useful for cross-compiling Certbot snaps.

# Resolve the Snap architecture to Docker architecture (DOCKER_ARCH variable)
# and QEMU architecture (QEMU_ARCH variable).
# Usage: ResolveArch [amd64|arm64|armhf]
ResolveArch() {
    local SNAP_ARCH=$1

    case "${SNAP_ARCH}" in
        "amd64")
            DOCKER_ARCH="amd64"
            QEMU_ARCH="x86_64"
            ;;
        "arm64")
            DOCKER_ARCH="arm64v8"
            QEMU_ARCH="aarch64"
            ;;
        "armhf")
            DOCKER_ARCH="arm32v7"
            QEMU_ARCH="arm"
            ;;
        "*")
            echo "Not supported build architecture '$1'." >&2
            exit 1
    esac
}

# Downloads QEMU static binary file for architecture
# Usage: DownloadQemuStatic [x86_64|aarch64|arm] DEST_DIR
DownloadQemuStatic() {
    local QEMU_ARCH=$1
    local DEST_DIR=$2
    local QEMU_DOWNLOAD_URL
    local QEMU_LATEST_TAG

    if [ ! -f "${DIR}/qemu-${QEMU_ARCH}-static" ]; then
        QEMU_DOWNLOAD_URL="https://github.com/multiarch/qemu-user-static/releases/download"
        QEMU_LATEST_TAG=$(curl -s https://api.github.com/repos/multiarch/qemu-user-static/tags \
            | grep 'name.*v[0-9]' \
            | head -n 1 \
            | cut -d '"' -f 4)
        echo "${QEMU_DOWNLOAD_URL}/${QEMU_LATEST_TAG}/x86_64_qemu-${QEMU_ARCH}-static.tar.gz"
        curl -SL "${QEMU_DOWNLOAD_URL}/${QEMU_LATEST_TAG}/x86_64_qemu-${QEMU_ARCH}-static.tar.gz" \
            | tar xzv -C "${DEST_DIR}"
    fi
}

# Executes the QEMU register script
# Usage: RegisterQemuHandlers
RegisterQemuHandlers() {
    docker run --rm --privileged multiarch/qemu-user-static:register --reset
}
