#!/bin/bash
set -euxo pipefail

# This script tests certbot docker and certbot dns plugin images.

# Usage: 
#       ./test.sh <tag> all
#       ./test.sh <tag> <architectures>
#   The <tag> argument is used to identify the code version (e.g v2.3.1) or type of build
#   (e.g. nightly). This will be used when saving images to the docker image cache.
#   The argument "all" will build all know architectures. Alternatively, the
#   user may provide a comma separated list of architectures drawn from the
#   known architectures. Known architectures include amd64, arm32v6, and arm64v8.

source "$(realpath $(dirname "${BASH_SOURCE[0]}"))/lib/common"

ParseArgs "$@"

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap popd EXIT

InstallMultiarchSupport


REGISTRY_SPEC="${DOCKER_HUB_ORG}/"

TestImage() {
    IMAGE_NAME=$1
    TAG_ARCH=$2
    TAG_VER=$3
    docker run --rm "${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_ARCH}-${TAG_VER}" plugins --prepare
}


for TAG_ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
    TestImage certbot "$TAG_ARCH" "$TAG_VER"
    for PLUGIN in "${CERTBOT_PLUGINS[@]}"; do
        TestImage "$PLUGIN" "$TAG_ARCH" "$TAG_VER"
    done
done