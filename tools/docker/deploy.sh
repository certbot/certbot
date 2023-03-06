#!/bin/bash
set -euxo pipefail

# This script builds certbot docker and certbot dns plugins docker using the
# local Certbot files.

# Usage: 
#       ./deploy.sh <TAG> all
#       ./deploy.sh <TAG> <architectures>
#   The <TAG> argument is an identifier applied to all docker images and manifests.
#   It may be something like `nightly` or `v2.3.2`. If the tag is a version
#   stamp greater than v2.0.0, then a `latest` tag will also be generated and
#   pushed to the docker hub repo.
#   The argument "all" will build all know architectures. Alternatively, the
#   user may provide a comma separated list of architectures drawn from the
#   known architectures. Know architectures include amd64, arm32v6, and arm64v8.

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
