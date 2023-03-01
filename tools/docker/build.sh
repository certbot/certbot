#!/bin/bash
set -euxo pipefail
IFS=$'\n\t'

# This script builds certbot docker and certbot dns plugins docker using the
# local Certbot files.

# Usage: ./build.sh [TAG] [all|amd64|arm32v6|arm64v8]
#   with the [TAG] value corresponding the base of the tag to give the Docker
#   images and the 2nd value being the architecture to build snaps for.
#   Values for the tag should be something like `v0.34.0` or `nightly`. The
#   given value is only the base of the tag because the things like the CPU
#   architecture are also added to the full tag.

WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
REPO_ROOT="$(dirname "$(dirname "${WORK_DIR}")")"
source "$WORK_DIR/lib/common"

trap Cleanup EXIT

Cleanup() {
    rm -rf "$REPO_ROOT"/qemu-*-static || true
    for plugin in "${CERTBOT_PLUGINS[@]}"; do
        rm -rf "$REPO_ROOT/certbot-$plugin"/qemu-*-static || true
    done
}

# Returns the translation from Docker to QEMU architecture
# Usage: GetQemuArch [amd64|arm32v6|arm64v8]
GetQemuArch() {
    ARCH=$1

    case "$ARCH" in
        "amd64")
            echo "x86_64"
            ;;
        "arm32v6")
            echo "arm"
            ;;
        "arm64v8")
            echo "aarch64"
            ;;
        "*")
            echo "Not supported build architecture '$1'." >&2
            exit 1
    esac
}

# Downloads QEMU static binary file for architecture
# Usage: DownloadQemuStatic [x86_64|arm|aarch64]
DownloadQemuStatic() {
    ARCH=$1

    QEMU_ARCH=$(GetQemuArch "$ARCH")
    if [ ! -f "qemu-${QEMU_ARCH}-static" ]; then
        QEMU_DOWNLOAD_URL="https://github.com/multiarch/qemu-user-static/releases/download"
        QEMU_LATEST_TAG=$(curl -s https://api.github.com/repos/multiarch/qemu-user-static/tags \
            | grep 'name.*v[0-9]' \
            | head -n 1 \
            | cut -d '"' -f 4)
        curl -SL "${QEMU_DOWNLOAD_URL}/${QEMU_LATEST_TAG}/x86_64_qemu-$QEMU_ARCH-static.tar.gz" \
            | tar xzv
    fi
}

TAG_BASE="$1"
if [ -z "$TAG_BASE" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi
ParseRequestedArch "${2}"

# Register QEMU handlers
docker run --rm --privileged multiarch/qemu-user-static:register --reset

# Step 1: Certbot core Docker
DOCKER_REPO="${DOCKER_HUB_ORG}/certbot"
for TARGET_ARCH in "${ALL_REQUESTED_ARCH[@]}"; do
    pushd "${REPO_ROOT}"
    DownloadQemuStatic "${TARGET_ARCH}"
    QEMU_ARCH=$(GetQemuArch "${TARGET_ARCH}")
    DOCKER_BUILDKIT=0 docker build \
        --build-arg TARGET_ARCH="${TARGET_ARCH}" \
        --build-arg QEMU_ARCH="${QEMU_ARCH}" \
        -f "${WORK_DIR}/core/Dockerfile" \
        -t "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}" \
        .
    popd
done

# Step 2: Certbot DNS plugins Docker images
for plugin in "${CERTBOT_PLUGINS[@]}"; do
    DOCKER_REPO="${DOCKER_HUB_ORG}/${plugin}"
    pushd "${REPO_ROOT}/certbot-${plugin}"
    # Copy QEMU static binaries downloaded when building the core Certbot image
    cp ../qemu-*-static .
    for TARGET_ARCH in "${ALL_REQUESTED_ARCH[@]}"; do
        QEMU_ARCH=$(GetQemuArch "${TARGET_ARCH}")
        BASE_IMAGE="${DOCKER_HUB_ORG}/certbot:${TARGET_ARCH}-${TAG_BASE}"
        DOCKER_BUILDKIT=0 docker build \
            --build-arg BASE_IMAGE="${BASE_IMAGE}" \
            --build-arg QEMU_ARCH="${QEMU_ARCH}" \
            -f "${WORK_DIR}/plugin/Dockerfile" \
            -t "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}" \
            .
    done
    popd
done
