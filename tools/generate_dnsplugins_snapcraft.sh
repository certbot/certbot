#!/bin/bash
# Generate the snapcraft.yaml file for all DNS plugins
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CERTBOT_DIR="$(dirname "${DIR}")"

for PLUGIN_PATH in "${CERTBOT_DIR}"/certbot-dns-*; do
  PLUGIN=$(basename "${PLUGIN_PATH}")
  DESCRIPTION=$(grep description "${PLUGIN_PATH}/setup.py" | sed -E 's|\s+description="(.*)",|\1|g')
  mkdir -p "${PLUGIN_PATH}/snap"
  cat <<EOF > "${PLUGIN_PATH}/snap/snapcraft.yaml"
name: ${PLUGIN}
summary: ${DESCRIPTION}
description: ${DESCRIPTION}
confinement: strict
grade: devel
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
      - EXCLUDE_CERTBOT_DEPS: "True"

slots:
  certbot:
    interface: content
    content: certbot-1
    read:
      - \$SNAP/lib/python3.8/site-packages
EOF
done
