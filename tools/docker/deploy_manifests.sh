#!/bin/bash
set -euxo pipefail

# This script generates multi-arch manifests for images previously pushed to
# Docker Hub via deploy_images.sh

# Usage: 
#       ./deploy_manifest.sh <TAG> all
#       ./deploy_manifest.sh <TAG> <architectures>
#   The <TAG> argument is an identifier applied to all docker images and manifests.
#   It may be something like `nightly` or `v2.3.2`. If the tag is a version
#   stamp greater than v2.0.0, then a `latest` tag will also be generated and
#   pushed to the docker hub repo.
#   The argument "all" will push all know architectures. Alternatively, the
#   user may provide a comma separated list of architectures drawn from the
#   known architectures. Know architectures include amd64, arm32v6, and arm64v8.


source "$(realpath $(dirname ${BASH_SOURCE[0]}))/lib/common"

TAG_VER="$1"
if [ -z "$TAG_VER" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi
REQUESTED_ARCH_LIST=$(InterpretArchRequest "$2")

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap popd EXIT

REGISTRY_SPEC="${DOCKER_HUB_ORG}/"

DeployManifest() {
    IMAGE_NAME=$1
    local IFS=","
    read -ra REQUESTED_ARCH_ARRAY <<< ${REQUESTED_ARCH_LIST}
    TAG_VER=$3

    IFS=" "
    
    SRC_IMAGES=""
    for TAG_ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
        SRC_IMAGES+="${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_ARCH}-${TAG_VER} "
    done
    docker buildx imagetools create -t ${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_VER} $SRC_IMAGES

    if [[ "${TAG_VER}" =~ ^v([2-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$ ]]; then
        docker buildx imagetools create -t ${REGISTRY_SPEC}${IMAGE_NAME}:latest $SRC_IMAGES
    fi
}

DeployManifest certbot ${REQUESTED_ARCH_LIST} $TAG_VER
for PLUGIN in "${CERTBOT_PLUGINS[@]}"; do
    DeployManifest $PLUGIN ${REQUESTED_ARCH_LIST} $TAG_VER
done




