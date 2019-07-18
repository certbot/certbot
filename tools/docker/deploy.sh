#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# This script deploys a new version of certbot dockers (core+plugins) regarding a released version of Certbot.
# The README.md is updated to include the reference of this new version, and a tag version is pushed to the
# Certbot Docker repository, triggering the DockerHub autobuild feature that will take care of the release.

# Usage: ./deploy.sh [VERSION]
#   with [VERSION] corresponding to a released version of certbot, like `v0.34.0`

trap Cleanup 1 2 3 6

Cleanup() {
    popd 2> /dev/null || true
}

WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

CERTBOT_DOCKER_VERSION="$1"  # Eg. v0.35.0 or v0.35.0-1
CERTBOT_VERSION=$(sed -E -e 's|(v[0-9+]\.[0-9]+\.[0-9]+).*|\1|g' <<< $CERTBOT_DOCKER_VERSION)  # Eg. v0.35.0
BRANCH_NAME=$(sed -E -e 's|v(.*)\.[0-9]+|\1.x|g' <<< $CERTBOT_VERSION)  # Eg. 0.35.x

sed -i -e "s|current-.*-blue\.svg|current-$CERTBOT_VERSION-blue.svg|g" core/README.md
sed -i -e "s|branch=.*)\]|branch=$BRANCH_NAME)]|g" core/README.md

sed -i -e "s|current-.*-blue\.svg|current-$CERTBOT_VERSION-blue.svg|g" plugin/README.md
sed -i -e "s|branch=.*)\]|branch=$BRANCH_NAME)]|g" plugin/README.md

pushd "$WORK_DIR"
    git commit -a -m "Release version $CERTBOT_DOCKER_VERSION" --allow-empty
    git tag "$CERTBOT_DOCKER_VERSION"
    git push
    git push --tags
popd
