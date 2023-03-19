#!/bin/bash
set -euxo pipefail

# This script builds certbot docker and certbot dns plugins docker using the
# local Certbot files. Results are stored in a docker cache on the local
# filesystem

# Usage: 
#       ./build.sh <tag> all 
#       ./build.sh <tag> <architectures> 
#   The <tag> argument is used to identify the code version (e.g v2.3.1) or type of build
#   (e.g. nightly). This will be used when saving images to the docker image cache.
#   The argument "all" will build all know architectures. Alternatively, the
#   user may provide a comma separated list of architectures drawn from the
#   known architectures. Know architectures include amd64, arm32v6, and arm64v8.

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

BuildAll() {
    docker buildx bake -f ${WORK_DIR}/docker-bake.hcl \
        --builder certbot_builder  \
        --set *.cache-to=type=local,dest=.docker_cache \
        build-all
}
# --progress plain
BuildAndCacheByArch() {
    export TAG_ARCH=$1
    docker buildx bake -f ${WORK_DIR}/docker-bake.hcl \
        --builder certbot_builder  \
        --set *.platform=$(arch2platform ${TAG_ARCH}) \
        --set *.cache-from=type=local,src=.docker_cache \
        build-all --load
}

# If the request was for all, max out the buildkit parallelization logic
if [ "$ARCH_LIST" = "all" ]; then
    BuildAll
fi
# split arch list into an array for per-arch saving of images to the docker image cache
IFS_OLD="$IFS"
IFS=","
read -ra REQUESTED_ARCH_ARRAY <<< $(InterpretArchRequest "$ARCH_LIST")
IFS="$IFS_OLD"
for ARCH in "${REQUESTED_ARCH_ARRAY[@]}"; do
    # If the build was already done by BuildAll, then the existing image is pulled
    # from the build cache. Otherwise, it gets built on demand here.
    # Either way, images get tagged and loaded to the docker image cache
    # for use by test and deploy
    BuildAndCacheByArch $ARCH
done    


