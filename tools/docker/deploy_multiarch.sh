#!/bin/bash
set -euxo pipefail

WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

TAG_BASE="$1"  # Eg. v0.35.0 or nightly
if [ -z "$TAG_BASE" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi
source "$WORK_DIR/lib/common"

# Creates multiarch manifests for TAG_BASE, and 'latest' if TAG_BASE > 2.0.0
#  - certbot/certbot:v2.2.0             <- multiarch manifest 
#  - certbot/certbot:latest             <- multiarch manifest
MakeMultiarchManifestForAllTargetArch() {
    DOCKER_REPO="${DOCKER_HUB_ORG}/${1}"
    SRC_IMAGES=""
    for TARGET_ARCH in "${ALL_TARGET_ARCH[@]}"; do
        SRC_IMAGES+=" ${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}"
    done
    echo ${SRC_IMAGES}
    docker buildx imagetools create -t ${DOCKER_REPO}:${TAG_BASE}${SRC_IMAGES}
    if [[ "${TAG_BASE}" =~ ^v([2-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$ ]]; then
        docker buildx imagetools create -t "${DOCKER_REPO}:latest" "${SRC_IMAGES}"
    fi
}


# Step 1: Certbot core Docker
MakeMultiarchManifestForAllTargetArch "certbot"

# Step 2: Certbot DNS plugins Docker images
for plugin in "${CERTBOT_PLUGINS[@]}"; do
    MakeMultiarchManifestForAllTargetArch "${plugin}"
done
