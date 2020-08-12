#!/bin/bash
set -euxo pipefail
IFS=$'\n\t'

# This script builds certbot docker and certbot dns plugins docker using the
# local Certbot files.  The build is currently done following the environment used by
# Dockerhub since this code previously used Docker Hub's automated build feature.

# Usage: ./build.sh [TAG]
#   with [TAG] corresponding the base of the tag to give the Docker images.
#   Values should be something like `v0.34.0` or `nightly`. The given value is
#   only the base of the tag because the things like the CPU architecture are
#   also added to the full tag.

# As of writing this, runs of this script consistently fail in Azure
# Pipelines, but they are fixed by using Docker BuildKit. A log of the failures
# that were occurring can be seen at
# https://gist.github.com/2227a05622299ce17bff9b0da714a1ff. Since using
# BuildKit is supposed to offer benefits anyway (see
# https://docs.docker.com/develop/develop-images/build_enhancements/ for more
# information), let's use it.
#
# This variable is set inside the script itself rather than in something like
# the CI config to have a consistent experience when this script is run
# locally.
export DOCKER_BUILDKIT=1

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

Build() {
    DOCKER_REPO="$1"
    TAG_BASE="$2"
    CONTEXT_PATH="$3"
    DOCKERFILE_DIR="$4"
    DOCKERFILE_PATH="$DOCKERFILE_DIR/Dockerfile"
    pushd "$CONTEXT_PATH"
        DOCKER_TAG="$TAG_BASE" DOCKER_REPO="$DOCKER_REPO" DOCKERFILE_PATH="$DOCKERFILE_PATH" bash "$DOCKERFILE_DIR/hooks/pre_build"
        DOCKER_TAG="$TAG_BASE" DOCKER_REPO="$DOCKER_REPO" DOCKERFILE_PATH="$DOCKERFILE_PATH" bash "$DOCKERFILE_DIR/hooks/build"
    popd
}

TAG_BASE="$1"
if [ -z "$TAG_BASE" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi

# Step 1: Certbot core Docker
Build "$DOCKER_HUB_ORG/certbot" "$TAG_BASE" "$REPO_ROOT" "$WORK_DIR/core"

# Step 2: Certbot DNS plugins Docker images
for plugin in "${CERTBOT_PLUGINS[@]}"; do
    Build "$DOCKER_HUB_ORG/$plugin" "$TAG_BASE" "$REPO_ROOT/certbot-$plugin" "$WORK_DIR/plugin"
done

Cleanup
