#!/bin/bash
set -euxo pipefail

# This script builds certbot docker and certbot dns plugins docker using the
# local Certbot files.

# Usage: ./deploy.sh [TAG] [all|<comma separated list of arch identifiers>]
#   with the [TAG] value corresponding the base of the tag to give the Docker
#   images and the 2nd value being the architecture to build snaps for.
#   Values for the tag should be something like `v0.34.0` or `nightly`. The
#   given value is only the base of the tag because the things like the CPU
#   architecture are also added to the full tag.

source "$(realpath $(dirname ${BASH_SOURCE[0]}))/lib/common"

TAG_BASE="$1"
if [ -z "$TAG_BASE" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi
REQUESTED_ARCH_LIST=$(InterpretArchRequest "$2")
PLATFORM_SPEC=$(archList2platformList "${REQUESTED_ARCH_LIST[@]}")

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap Cleanup EXIT

CreateBuilder

# Helper function to generate latest tag if appropriate
LatestTag() {
    TAG_BASE=$1
    if [[ "${TAG_BASE}" =~ ^v([2-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$ ]]; then
        echo "-t ${DOCKER_REPO}:latest"
    fi
}

# Helper function to deploy certbot image with version and optional latest tag
DeployCertbot() {
    DOCKER_REPO="${DOCKER_HUB_ORG}/certbot"

    docker buildx build \
        $(StandardCertbotBuildArgs ${PLATFORM_SPEC}) \
        -t ${DOCKER_REPO}:${TAG_BASE} $(LatestTag ${TAG_BASE}) \
        --push \
        .
}

# Helper function to deploy plugin image with version and optional latest tag
DeployPlugin() {
    PLUGIN=$1
    DOCKER_REPO="${DOCKER_HUB_ORG}/${PLUGIN}"
    docker buildx build \
        $(StandardPluginBuildArgs ${PLATFORM_SPEC} ${PLUGIN}) \
        -t ${DOCKER_REPO}:${TAG_BASE} $(LatestTag ${TAG_BASE}) \
        --push \
        .
}

# Step 1: Certbot core Docker
DeployCertbot

# Step 2: Certbot DNS plugins Docker images
for PLUGIN in "${CERTBOT_PLUGINS[@]}"; do
    DeployPlugin $PLUGIN
done
