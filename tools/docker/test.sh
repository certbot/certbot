#!/bin/bash
set -euxo pipefail

# This script tests certbot docker and certbot dns plugin images.

# Usage: 
#       ./test.sh all
#       ./test.sh <architectures>
#   The argument "all" will build all know architectures. Alternatively, the
#   user may provide a comma separated list of architectures drawn from the
#   known architectures. Know architectures include amd64, arm32v6, and arm64v8.

source "$(realpath $(dirname ${BASH_SOURCE[0]}))/lib/common"

REQUESTED_ARCH_LIST=$(InterpretArchRequest "$1")

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
