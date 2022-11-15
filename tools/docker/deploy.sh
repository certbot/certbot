#!/bin/bash
set -euxo pipefail
IFS=$'\n\t'

# This script deploys new versions of Certbot and Certbot plugin docker images.

# Usage: ./deploy.sh [TAG] [all|amd64|arm32v6|arm64v8]
#   with the [TAG] value corresponding the base of the tag to give the Docker
#   images and the 2nd value being the architecture to build snaps for.
#   Values should be something like `v0.34.0` or `nightly`. The given value is
#   only the base of the tag because the things like the CPU architecture are
#   also added to the full tag.

WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

TAG_BASE="$1"  # Eg. v0.35.0 or nightly
if [ -z "$TAG_BASE" ]; then
    echo "We cannot tag Docker images with an empty string!" >&2
    exit 1
fi
source "$WORK_DIR/lib/common"
ParseRequestedArch "${2}"

# Creates and pushes all Docker images aliases for the requested architectures
# set in the environment variable ALL_REQUESTED_ARCH.  If the value of the
# global variable TAG_BASE is a 2.0.0 or greater version tag such as v2.1.0,
# the "latest" tag is also updated. Tags without the architecture part are also
# created for the default architecture.
# As an example, for amd64 (the default architecture) and the tag v0.35.0, the
# following tags would be created:
#  - certbot/certbot:v0.35.0
#  - certbot/certbot:latest
#  - certbot/certbot:amd64-latest
# For the architecture arm32v6 and the tag v0.35.0, only the following tag
# would be created:
#  - certbot/certbot:arm32v6-latest
# For other tags such as "nightly", aliases are only created for the default
# architecture where the tag "nightly" would be used without an architecture
# part.
# Usage: TagAndPushForAllRequestedArch [IMAGE NAME]
#   where [IMAGE NAME] is the name of the Docker image in the Docker repository
#   such as "certbot" or "dns-cloudflare".
# Read globals:
# * TAG_BASE
# * ALL_REQUESTED_ARCH
TagAndPushForAllRequestedArch() {
    DOCKER_REPO="${DOCKER_HUB_ORG}/${1}"
    for TARGET_ARCH in "${ALL_REQUESTED_ARCH[@]}"; do
        # NOTE: In early 2022, we were experiencing regular "docker push"
        # timeouts, so we added these "--debug" flags to learn more. Since we
        # added them, we haven't had another timeout, so until we experience
        # another timeout & can get the deubg logs, we're leaving them in.
        echo Would have pushed "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}"

        # If TAG_BASE is a valid tag for version 2.0.0 or greater
        if [[ "${TAG_BASE}" =~ ^v([2-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$ ]]; then
            docker tag "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}" "${DOCKER_REPO}:${TARGET_ARCH}-latest"
            echo Would have pushed "${DOCKER_REPO}:${TARGET_ARCH}-latest"
            if [ "${TARGET_ARCH}" == "${DEFAULT_ARCH}" ]; then
                docker tag "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}" "${DOCKER_REPO}:latest"
                echo Would have pushed "${DOCKER_REPO}:latest"
            fi
        fi
        if [ "${TARGET_ARCH}" == "${DEFAULT_ARCH}" ]; then
            docker tag "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}" "${DOCKER_REPO}:${TAG_BASE}"
            echo Would have pushed "${DOCKER_REPO}:${TAG_BASE}"
        fi
    done
}

# Step 1: Certbot core Docker
TagAndPushForAllRequestedArch "certbot"

# Step 2: Certbot DNS plugins Docker images
for plugin in "${CERTBOT_PLUGINS[@]}"; do
    TagAndPushForAllRequestedArch "${plugin}"
done
