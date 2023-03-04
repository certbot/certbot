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
    docker builder rm certbot_builder || true
    popd
}

TAG_BASE="$1"
if [ -z "$TAG_BASE" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi
ParseRequestedArch "${2}"

# just incase the env is not perfectly clean, remove any old instance of the builder
docker builder rm certbot_builder || true
# create the builder instance
docker buildx create --name certbot_builder --driver docker-container --driver-opt=network=host --bootstrap --use
# add binfmt tools to the docker environment, with integration into the new builder instance
docker run --privileged --rm tonistiigi/binfmt --install all

# Step 1: Certbot core Docker
pushd "${REPO_ROOT}"
DOCKER_REPO="${DOCKER_HUB_ORG}/certbot"
for TARGET_ARCH in "${ALL_REQUESTED_ARCH[@]}"; do
    docker buildx build \
        --platform $(getPlatform $TARGET_ARCH) \
        --target certbot \
        -f "${WORK_DIR}/Dockerfile" \
        -t "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}" \
        --load \
        .

done

# Step 2: Certbot DNS plugins Docker images
for plugin in "${CERTBOT_PLUGINS[@]}"; do
    DOCKER_REPO="${DOCKER_HUB_ORG}/${plugin}"
    # Copy QEMU static binaries downloaded when building the core Certbot image
    for TARGET_ARCH in "${ALL_REQUESTED_ARCH[@]}"; do
        docker buildx build \
            --platform $(getPlatform $TARGET_ARCH) \
            --target certbot-plugin \
            --build-context plugin-src="${REPO_ROOT}/certbot-${plugin}" \
            -f "${WORK_DIR}/Dockerfile" \
            -t "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}" \
            --load \
            .
    done
done

# popd
