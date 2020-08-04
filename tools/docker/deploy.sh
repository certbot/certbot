#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# This script deploys new versions of Certbot and Certbot plugin docker images.
# This process is currently done using a similar approach to Docker Hub since
# this code previously used Docker Hub's automated build feature.

# Usage: ./deploy.sh [TAG]
#   with [TAG] corresponding the base of the tag to give the Docker images.
#   Values should be something like `v0.34.0` or `nightly`. The given value is
#   only the base of the tag because the things like the CPU architecture are
#   also added to the full tag.

trap Cleanup 1 2 3 6

Cleanup() {
    popd 2> /dev/null || true
}

WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

Deploy() {
    DOCKER_REPO="$1"
    TAG_BASE="$2"
    DOCKERFILE_DIR="$3"
    DOCKERFILE_PATH="$DOCKERFILE_DIR/Dockerfile"
    DOCKER_TAG="$TAG_BASE" DOCKER_REPO="$DOCKER_REPO" DOCKERFILE_PATH="$DOCKERFILE_PATH" bash "$DOCKERFILE_DIR/hooks/push"
    DOCKER_TAG="$TAG_BASE" DOCKER_REPO="$DOCKER_REPO" DOCKERFILE_PATH="$DOCKERFILE_PATH" bash "$DOCKERFILE_DIR/hooks/post_push"
}

TAG_BASE="$1"  # Eg. v0.35.0 or nightly
source "$WORK_DIR/lib/common"

# Step 1: Certbot core Docker
Deploy "$DOCKER_HUB_ORG/certbot" "$TAG_BASE" "$WORK_DIR/core"

# Step 2: Certbot DNS plugins Docker images
for plugin in "${CERTBOT_PLUGINS[@]}"; do
    Deploy "$DOCKER_HUB_ORG/$plugin" "$TAG_BASE" "$WORK_DIR/plugin"
done
