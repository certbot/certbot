#!/bin/bash
# Generate the snapcraft.yaml file for a DNS plugins
# Usage: bash generate_dnsplugins_snapcraft.sh path/to/dns/plugin
# For example, from the certbot home directory:
#   tools/snap/generate_dnsplugins_snapcraft.sh certbot-dns-dnsimple
set -e

PLUGIN_PATH=$1
PLUGIN=$(basename "${PLUGIN_PATH}")
DESCRIPTION=$(sed -E -n "/[[:space:]]+description=/ s/[[:space:]]+description=['\"](.*)['\"],/\1/ p" "${PLUGIN_PATH}/setup.py")
mkdir -p "${PLUGIN_PATH}/snap"
cat <<EOF > "${PLUGIN_PATH}/snap/snapcraft.yaml"
# This file is generated automatically and should not be edited manually.
name: ${PLUGIN}
summary: ${DESCRIPTION}
description: ${DESCRIPTION}
confinement: strict
grade: stable
base: core20
adopt-info: ${PLUGIN}

parts:
  ${PLUGIN}:
    plugin: python
    source: .
    override-pull: |
        snapcraftctl pull
        snapcraftctl set-version \`grep ^version \$SNAPCRAFT_PART_SRC/setup.py | cut -f2 -d= | tr -d "'[:space:]"\`
    build-environment:
      # We set this environment variable while building to try and increase the
      # stability of fetching the rust crates needed to build the cryptography
      # library.
      - CARGO_NET_GIT_FETCH_WITH_CLI: "true"
      # Constraints are passed through the environment variable PIP_CONSTRAINTS instead of using the
      # parts.[part_name].constraints option available in snapcraft.yaml when the Python plugin is
      # used. This is done to let these constraints be applied not only on the certbot package
      # build, but also on any isolated build that pip could trigger when building wheels for
      # dependencies. See https://github.com/certbot/certbot/pull/8443 for more info.
      - PIP_CONSTRAINT: \$SNAPCRAFT_PART_SRC/snap-constraints.txt
      - SNAP_BUILD: "True"
    # To build cryptography and cffi if needed
    build-packages:
      - gcc
      - git
      - build-essential
      - libssl-dev
      - libffi-dev
      - python3-dev
      - cargo
  certbot-metadata:
    plugin: dump
    source: .
    stage: [setup.py, certbot-shared]
    override-pull: |
        snapcraftctl pull
        mkdir -p \$SNAPCRAFT_PART_SRC/certbot-shared

slots:
  certbot:
    interface: content
    content: certbot-1
    read:
      - \$SNAP/lib/python3.8/site-packages

plugs:
  certbot-metadata:
    interface: content
    content: metadata-1
    target: \$SNAP/certbot-shared
EOF
