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
# tags for "latest" are also created. Tags such as "nightly" do not recieve 
# "latest" tags.
# As an example, for the tag v2.2.0 and the default set of all target 
# architectures as of writing this, the following tags would be created:
#  - certbot/certbot:amd64-v2.2.0       <- image
#  - certbot/certbot:arm32v6-v2.2.0     <- image
#  - certbot/certbot:arm64v8-v2.2.0     <- image
#  - certbot/certbot:amd64-latest       <- image
#  - certbot/certbot:arm32v6-latest     <- image
#  - certbot/certbot:arm64v8-latest     <- image
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
        docker --debug push "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}"
        if [[ "${TAG_BASE}" =~ ^v([2-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$ ]]; then
            docker tag "${DOCKER_REPO}:${TARGET_ARCH}-${TAG_BASE}" "${DOCKER_REPO}:${TARGET_ARCH}-latest"
            docker --debug push "${DOCKER_REPO}:${TARGET_ARCH}-latest"
        fi
    done
}

# Step 1: Certbot core Docker
TagAndPushForAllRequestedArch "certbot"

# Step 2: Certbot DNS plugins Docker images
for plugin in "${CERTBOT_PLUGINS[@]}"; do
    TagAndPushForAllRequestedArch "${plugin}"
done
