#!/bin/bash
# Generate all necessary files for building snaps for all DNS plugins
set -eu

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CERTBOT_DIR="$(dirname "$(dirname "${DIR}")")"

for PLUGIN_PATH in "${CERTBOT_DIR}"/certbot-dns-*; do
  bash "${CERTBOT_DIR}"/tools/snap/generate_dnsplugins_snapcraft.sh $PLUGIN_PATH
  bash "${CERTBOT_DIR}"/tools/snap/generate_dnsplugins_postrefreshhook.sh $PLUGIN_PATH
  # Create constraints file
  "${CERTBOT_DIR}"/tools/merge_requirements.py tools/dev_constraints.txt \
    <("${CERTBOT_DIR}"/tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt) \
    <("${CERTBOT_DIR}"/tools/strip_hashes.py tools/pipstrap_constraints.txt) \
    > "${PLUGIN_PATH}"/snap-constraints.txt
done
