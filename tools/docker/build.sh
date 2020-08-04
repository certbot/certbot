#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# This script builds certbot docker and certbot dns plugins docker against a given release version of certbot.
# The build is done following the environment used by Dockerhub to handle its autobuild feature, and so can be
# used as a pre-deployment validation test.

# Usage: ./build.sh [VERSION]
#   with [VERSION] corresponding to a released version of certbot, like `v0.34.0`

trap Cleanup 1 2 3 6

Cleanup() {
    if [ ! -z "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"/core/qemu-*-static || true
        rm -rf "$WORK_DIR"/plugin/qemu-*-static || true
    fi
    popd 2> /dev/null || true
}

Build() {
    DOCKER_REPO="$1"
    CERTBOT_VERSION="$2"
    CONTEXT_PATH="$3"
    DOCKERFILE_PATH="$CONTEXT_PATH/Dockerfile"
    DOCKER_TAG="$CERTBOT_VERSION"
    pushd "$CONTEXT_PATH"
        DOCKER_TAG="$DOCKER_TAG" DOCKER_REPO="$DOCKER_REPO" DOCKERFILE_PATH="$DOCKERFILE_PATH" bash hooks/pre_build
        DOCKER_TAG="$DOCKER_TAG" DOCKER_REPO="$DOCKER_REPO" DOCKERFILE_PATH="$DOCKERFILE_PATH" bash hooks/build
    popd
}

WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

CERTBOT_VERSION="$1"

# Step 1: Certbot core Docker
Build "certbot/certbot" "$CERTBOT_VERSION" "$WORK_DIR/core"

# Step 2: Certbot dns plugins Dockers
CERTBOT_PLUGINS_DOCKER_REPOS=(
    "certbot/dns-dnsmadeeasy"
    "certbot/dns-dnsimple"
    "certbot/dns-ovh"
    "certbot/dns-cloudflare"
    "certbot/dns-cloudxns"
    "certbot/dns-digitalocean"
    "certbot/dns-google"
    "certbot/dns-luadns"
    "certbot/dns-nsone"
    "certbot/dns-rfc2136"
    "certbot/dns-route53"
    "certbot/dns-gehirn"
    "certbot/dns-linode"
    "certbot/dns-sakuracloud"
)

for DOCKER_REPO in "${CERTBOT_PLUGINS_DOCKER_REPOS[@]}"; do
    Build "${DOCKER_REPO}" "$CERTBOT_VERSION" "$WORK_DIR/plugin"
done

Cleanup
