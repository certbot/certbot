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



REGISTRY_SPEC="${DOCKER_HUB_ORG}/"

DeployImage() {
    IMAGE_NAME=$1
    TAG_ARCH=$2
    TAG_VER=$3
    docker push "${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_ARCH}-${TAG_VER}"
    if [[ "${TAG_BASE}" =~ ^v([2-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$ ]]; then
        docker tag "${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_ARCH}-${TAG_VER}" "${REGISTRY_SPEC}${IMAGE_NAME}:latest"
    fi
}

DeployManifest() {
    IMAGE_NAME=$1
    local IFS=","
    read -ra REQUESTED_ARCH_ARRAY <<< $(InterpretArchRequest "$2")
    TAG_VER=$3
    
    SRC_IMAGES=""
    for TAG_ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
        SRC_IMAGES+="${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_ARCH}-${TAG_VER} "
    done

    docker buildx imagetools create -t "${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_VER} $SRC_IMAGES"
}

for TAG_ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
    DeployImage certbot $TAG_ARCH $TAG_VER
    for PLUGIN in "${CERTBOT_PLUGINS[@]}"; do
        DeployImage $PLUGIN $TAG_ARCH $TAG_VER
    done
done


