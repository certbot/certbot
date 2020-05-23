#!/bin/bash
# Common bash functions useful for cross-compiling Certbot snaps.

# Returns the translation from Snap architecture to Docker architecture
# Usage: GetQemuArch [amd64|arm64|armhf]
GetDockerArch() {
    SNAP_ARCH=$1

    case "${SNAP_ARCH}" in
        "amd64")
            echo "amd64"
            ;;
        "arm64")
            echo "arm64v8"
            ;;
        "armhf")
            echo "arm32v7"
            ;;
        "*")
            echo "Not supported build architecture '$1'." >&2
            exit 1
    esac
}

# Returns the translation from Snap architecture to QEMU architecture
# Usage: GetQemuArch [amd64|arm64|armhf]
GetQemuArch() {
    SNAP_ARCH=$1

    case "${SNAP_ARCH}" in
        "amd64")
            echo "x86_64"
            ;;
        "arm64")
            echo "aarch64"
            ;;
        "armhf")
            echo "arm"
            ;;
        "*")
            echo "Not supported build architecture '$1'." >&2
            exit 1
    esac
}

# Downloads QEMU static binary file for architecture
# Usage: DownloadQemuStatic [x86_64|aarch64|arm] DEST_DIR
DownloadQemuStatic() {
    QEMU_ARCH=$1
    DEST_DIR=$2

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
