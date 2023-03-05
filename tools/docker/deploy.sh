#!/bin/bash
set -euxo pipefail
# IFS=$'\n\t'

# This script builds certbot docker and certbot dns plugins docker using the
# local Certbot files.

# Usage: ./build.sh [TAG] [all|<comma separated list of arch identifiers>]
#   with the [TAG] value corresponding the base of the tag to give the Docker
#   images and the 2nd value being the architecture to build snaps for.
#   Values for the tag should be something like `v0.34.0` or `nightly`. The
#   given value is only the base of the tag because the things like the CPU
#   architecture are also added to the full tag.

WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
REPO_ROOT="$(dirname "$(dirname "${WORK_DIR}")")"
source "$WORK_DIR/lib/common"

TAG_BASE="$1"
if [ -z "$TAG_BASE" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi
PLATFORM_SPEC=$(archList2platformList "${2}")

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap Cleanup EXIT
Cleanup() {
    docker builder rm certbot_builder || true
    popd
}



# just incase the env is not perfectly clean, remove any old instance of the builder
docker builder rm certbot_builder || true
# create the builder instance
docker buildx create --name certbot_builder --driver docker-container --driver-opt=network=host --bootstrap --use
# add binfmt tools to the docker environment, with integration into the new builder instance
docker run --privileged --rm tonistiigi/binfmt --install all



# Step 1: Certbot core Docker
DOCKER_REPO="${DOCKER_HUB_ORG}/certbot"
docker buildx build \
    --platform ${PLATFORM_SPEC} \
    --target certbot \
    -f "${WORK_DIR}/Dockerfile" \
    --cache-from=type=local,src=${REPO_ROOT}/docker_cache \
    --cache-to=type=local,dest=${REPO_ROOT}/docker_cache \
    -t certbot:${TAG_BASE} \
    --push \
    .

# Step 2: Certbot DNS plugins Docker images
for plugin in "${CERTBOT_PLUGINS[@]}"; do
    DOCKER_REPO="${DOCKER_HUB_ORG}/${plugin}"
    docker buildx build \
        --platform ${PLATFORM_SPEC} \
        --target certbot-plugin \
        --build-context plugin-src="${REPO_ROOT}/certbot-${plugin}" \
        -f "${WORK_DIR}/Dockerfile" \
        --cache-from=type=local,src=${REPO_ROOT}/docker_cache \
        --cache-to=type=local,dest=${REPO_ROOT}/docker_cache \
        -t certbot-${plugin}:${TAG_BASE} \
        --push \
        .
done
