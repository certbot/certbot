#!/bin/bash
set -euxo pipefail

# This script builds certbot docker and certbot dns plugins docker using the
# local Certbot files. Results are stored in a docker cache on the local
# filesystem

# Usage: 
#       ./build.sh all 
#       ./build.sh <architectures> 
#   The argument "all" will build all know architectures. Alternatively, the
#   user may provide a comma separated list of architectures drawn from the
#   known architectures. Know architectures include amd64, arm32v6, and arm64v8.

source "$(realpath $(dirname ${BASH_SOURCE[0]}))/lib/common"

REQUESTED_ARCH_LIST=$(InterpretArchRequest "$2")
PLATFORM_SPEC=$(archList2platformList "${REQUESTED_ARCH_LIST[@]}")

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap Cleanup EXIT

CreateBuilder

# Helper function to build certbot image
BuildCertbot() {
    docker buildx build \
        $(StandardCertbotBuildArgs ${PLATFORM_SPEC}) \
        --cache-to=type=local,dest=${DOCKER_CACHE}/certbot \
        .
}

# Helper function to build plugin image
BuildPlugin() {
    PLUGIN=$1
    docker buildx build \
        $(StandardPluginBuildArgs ${PLATFORM_SPEC} ${PLUGIN}) \
        --cache-to=type=local,dest=${DOCKER_CACHE}/${PLUGIN} \
        .
}

# Step 1: Certbot core Docker
BuildCertbot

# Step 2: Certbot DNS plugins Docker images
for PLUGIN in "${CERTBOT_PLUGINS[@]}"; do
    BuildPlugin $PLUGIN
done
