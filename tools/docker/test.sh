#!/bin/bash
set -euxo pipefail

WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
REPO_ROOT="$(dirname "$(dirname "${WORK_DIR}")")"
source "$WORK_DIR/lib/common"


TAG_BASE="$1"
if [ -z "$TAG_BASE" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi
PLATFORM_SPEC=$(archList2platformList "${2}")

#jump to root, matching popd handed by Cleanup on EXIT via trap
pushd "${REPO_ROOT}"

# Set trap here, as the popd won't work as expected if invoked prior to pushd
trap Cleanup EXIT
Cleanup() {
    docker builder rm certbot_builder || true
    popd
}



# just incase the env is not perfectly clean, remove any old instance of the builder
docker builder rm certbot_builder || true
# create the builder instance
docker buildx create --name certbot_builder --driver docker-container --driver-opt=network=host --bootstrap --use
# add binfmt tools to the docker environment, with integration into the new builder instance
docker run --privileged --rm tonistiigi/binfmt --install all




# Step 1: Certbot core Docker
DOCKER_REPO="${DOCKER_HUB_ORG}/certbot"
IFS_OLD="$IFS"
IFS=","
read -ra REQUESTED_ARCH_LIST <<< "$2"
IFS="$IFS_OLD"
for ARCH in "${REQUESTED_ARCH_LIST[@]}"; do

    docker buildx build \
        --platform $(arch2platform ${ARCH}) \
        --target certbot \
        -f "${WORK_DIR}/Dockerfile" \
        --cache-from=type=local,src=${REPO_ROOT}/docker_cache \
        --cache-to=type=local,dest=${REPO_ROOT}/docker_cache \
        -t certbot:${ARCH}-${TAG_BASE} \
        --load \
        .
    docker run --rm "certbot:${ARCH}-${TAG_BASE}" plugins --prepare

    # Step 2: Certbot DNS plugins Docker images
    for plugin in "${CERTBOT_PLUGINS[@]}"; do
        DOCKER_REPO="${DOCKER_HUB_ORG}/${plugin}"
        docker buildx build \
            --platform $(arch2platform ${ARCH}) \
            --target certbot-plugin \
            --build-context plugin-src="${REPO_ROOT}/certbot-${plugin}" \
            -f "${WORK_DIR}/Dockerfile" \
            --cache-from=type=local,src=${REPO_ROOT}/docker_cache \
            --cache-to=type=local,dest=${REPO_ROOT}/docker_cache \
            -t certbot-${plugin}:${ARCH}-${TAG_BASE} \
            --load \
            .
        docker run --rm "certbot-${plugin}:${ARCH}-${TAG_BASE}" plugins --prepare

    done

done
