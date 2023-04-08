#!/bin/bash
set -euxo pipefail

# This script takes docker images in the local docker cache and pushes them to
# Docker Hub.

# Usage: 
#       ./deploy_images.sh <TAG> all
#       ./deploy_images.sh <TAG> <architectures>
#   The <TAG> argument is an identifier applied to all docker images and manifests.
#   It may be something like `nightly` or `v2.3.2`. If the tag is a version
#   stamp greater than v2.0.0, then a `latest` tag will also be generated and
#   pushed to the docker hub repo.
#   The argument "all" will push all known architectures. Alternatively, the
#   user may provide a comma separated list of architectures drawn from the
#   known architectures. Known architectures include amd64, arm32v6, and arm64v8.

source "$(realpath $(dirname "${BASH_SOURCE[0]}"))/lib/common"

ParseArgs "$@"

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap popd EXIT

REGISTRY_SPEC="${DOCKER_HUB_ORG}/"

DeployImage() {
    IMAGE_NAME=$1
    TAG_ARCH=$2
    docker push "${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_ARCH}-${TAG_VER}"
    if [[ "${TAG_VER}" =~ ^v([2-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$ ]]; then
        docker tag "${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_ARCH}-${TAG_VER}" "${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_ARCH}-latest"
        docker push "${REGISTRY_SPEC}${IMAGE_NAME}:${TAG_ARCH}-latest"
    fi
}


for TAG_ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
    DeployImage certbot "$TAG_ARCH"
    for PLUGIN in "${CERTBOT_PLUGINS[@]}"; do
        DeployImage "$PLUGIN" "$TAG_ARCH"
    done
done