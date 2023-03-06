#!/bin/bash
set -euxo pipefail

# This script tests certbot docker and certbot dns plugin images.

# Usage: ./test.sh [TAG] [all|<comma separated list of arch identifiers>]
#   with the [TAG] value corresponding the base of the tag to give the Docker
#   images and the 2nd value being the architecture to build snaps for.
#   Values for the tag should be something like `v0.34.0` or `nightly`. The
#   given value is only the base of the tag because the things like the CPU
#   architecture are also added to the full tag.

source "$(realpath $(dirname ${BASH_SOURCE[0]}))/lib/common"

REQUESTED_ARCH_LIST=$(InterpretArchRequest "$2")

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap Cleanup EXIT

CreateBuilder


IFS_OLD="$IFS"
IFS=","
read -ra REQUESTED_ARCH_ARRAY <<< "$REQUESTED_ARCH_LIST"
IFS="$IFS_OLD"

# Helper function to load and test certbot image
TestCertbot() {
    ARCH=$1
    DOCKER_REPO="${DOCKER_HUB_ORG}/certbot"
    docker buildx build \
        $(StandardCertbotBuildArgs $(arch2platform ${ARCH})) \
        -t ${DOCKER_REPO}:${ARCH} \
        --load \
        .
    docker run --rm "${DOCKER_REPO}:${ARCH}" plugins --prepare
    docker rmi ${DOCKER_REPO}:${ARCH}
}

# Helper function to load and test plugin image
TestPlugin() {
    ARCH=$1
    PLUGIN=$2
    DOCKER_REPO="${DOCKER_HUB_ORG}/${PLUGIN}"
    docker buildx build \
        $(StandardPluginBuildArgs $(arch2platform ${ARCH}) ${PLUGIN}) \
        -t ${DOCKER_REPO}:${ARCH} \
        --load \
        .
    docker run --rm "${DOCKER_REPO}:${ARCH}" plugins --prepare
    docker rmi ${DOCKER_REPO}:${ARCH}
}

# Step 1: Certbot core Docker
for ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
    TestCertbot $ARCH
done    

# Step 2: Certbot DNS plugins Docker images
for ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
    for PLUGIN in "${CERTBOT_PLUGINS[@]}"; do
        TestPlugin $ARCH $PLUGIN
    done
done
