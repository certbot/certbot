#!/bin/bash
set -euxo pipefail

# This script builds docker images for certbot and each dns plugin from the
# local Certbot source files. Results are stored in the docker image cache

# Usage: 
#       ./build.sh <tag> all 
#       ./build.sh <tag> <architectures> 
#   The <tag> argument is used to identify the code version (e.g v2.3.1) or type of build
#   (e.g. nightly). This will be used when saving images to the docker image cache.
#   The argument "all" will build all known architectures. Alternatively, the
#   user may provide a comma separated list of architectures drawn from the
#   known architectures. Known architectures include amd64, arm32v6, and arm64v8.

source "$(realpath $(dirname ${BASH_SOURCE[0]}))/lib/common"

#used by docker buildx bake, so mark export
export TAG_VER="$1"
if [ -z "$TAG_VER" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi
ARCH_LIST="$2"
if [ -z "$ARCH_LIST" ]; then
    echo "Architectures must be specified!" >&2
    exit 1
fi

export REGISTRY_SPEC="${DOCKER_HUB_ORG}/"

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap Cleanup EXIT
# Create the builder
CreateBuilder


BuildAndCacheByArch() {
    TAG_ARCH=$1
    docker buildx build --target certbot --builder certbot_builder \
        --platform $(arch2platform $TAG_ARCH) \
        -f "${WORK_DIR}/Dockerfile" \
        -t "${REGISTRY_SPEC}certbot:${TAG_ARCH}-${TAG_VER}" \
        --load \
        .
    for plugin in "${CERTBOT_PLUGINS[@]}"; do
        docker buildx build --target certbot-plugin --builder certbot_builder \
            --platform $(arch2platform $TAG_ARCH) \
            --build-context plugin-src="${REPO_ROOT}/certbot-${plugin}" \
            -f "${WORK_DIR}/Dockerfile" \
            -t "${REGISTRY_SPEC}${plugin}:${TAG_ARCH}-${TAG_VER}" \
            --load \
            .
    done
}

# In principle, there is a better way to do with by using `docker buildx back`
# instead of a for-loop. However, issues have been found in the results
# of such a build. See git commit adf227fc4.

# split arch list into an array for per-arch image building and saving
IFS_OLD="$IFS"
IFS=","
read -ra REQUESTED_ARCH_ARRAY <<< $(InterpretArchRequest "$ARCH_LIST")
IFS="$IFS_OLD"
for ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
    BuildAndCacheByArch $ARCH
done    


