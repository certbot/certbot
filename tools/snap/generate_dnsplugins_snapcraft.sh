#!/bin/bash
# Generate the snapcraft.yaml file for a DNS plugins
# Usage: bash generate_dnsplugins_snapcraft.sh path/to/dns/plugin
# For example, from the certbot home directory:
#   tools/snap/generate_dnsplugins_snapcraft.sh certbot-dns-dnsimple
set -e

PLUGIN_PATH=$1
PLUGIN=$(basename "${PLUGIN_PATH}")
DESCRIPTION=$(grep description "${PLUGIN_PATH}/setup.py" | sed -E 's|\s+description="(.*)",|\1|g')
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
    constraints: [\$SNAPCRAFT_PART_SRC/snap-constraints.txt]
    override-pull: |
        snapcraftctl pull
        snapcraftctl set-version \`grep ^version \$SNAPCRAFT_PART_SRC/setup.py | cut -f2 -d= | tr -d "'[:space:]"\`
    build-environment:
      - SNAP_BUILD: "True"
    # To build cryptography and cffi if needed
    build-packages: [gcc, libffi-dev, libssl-dev, python3-dev]
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
