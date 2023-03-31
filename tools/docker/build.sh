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

ParseArgs $@

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap Cleanup EXIT
# Create the builder
CreateBuilder
InstallMultiarchSupport


BuildAndCacheByArch() {
    TAG_ARCH=$1
    docker buildx build --target certbot --builder certbot_builder \
        --platform $(arch2platform $TAG_ARCH) \
        -f "${WORK_DIR}/Dockerfile" \
        -t "${DOCKER_HUB_ORG}/certbot:${TAG_ARCH}-${TAG_VER}" \
        --load \
        .
    for plugin in "${CERTBOT_PLUGINS[@]}"; do
        docker buildx build --target certbot-plugin --builder certbot_builder \
            --platform $(arch2platform $TAG_ARCH) \
            --build-context plugin-src="${REPO_ROOT}/certbot-${plugin}" \
            -f "${WORK_DIR}/Dockerfile" \
            -t "${DOCKER_HUB_ORG}/${plugin}:${TAG_ARCH}-${TAG_VER}" \
            --load \
            .
    done
}

# In principle, there is a better way to do with by using `docker buildx bake`
# instead of a for-loop. However, issues have been found in the results
# of such a build. See the branch buildx-bake and
# https://github.com/certbot/certbot/issues/9587.

for ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
    BuildAndCacheByArch $ARCH
done    


