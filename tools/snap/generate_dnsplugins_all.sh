#!/bin/bash
# Generate all necessary files for building snaps for all DNS plugins
set -eu

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CERTBOT_DIR="$(dirname "$(dirname "${DIR}")")"

for PLUGIN_PATH in "${CERTBOT_DIR}"/certbot-dns-*; do
  bash "${CERTBOT_DIR}"/tools/snap/generate_dnsplugins_snapcraft.sh $PLUGIN_PATH
  bash "${CERTBOT_DIR}"/tools/snap/generate_dnsplugins_postrefreshhook.sh $PLUGIN_PATH
  # Create constraints file
  cp "${CERTBOT_DIR}"/tools/requirements.txt "${PLUGIN_PATH}"/snap-constraints.txt
done
