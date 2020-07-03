#!/bin/bash
# Cross-compile the specified Certbot DNS plugins snaps from local sources for the specified architecture.
# This script is designed for CI tests purpose.
# Usage: build.sh [amd64,arm64,armhf] [DNS_PLUGIN1,DNS_PLUGIN2 or ALL]
set -ex

SNAP_ARCH=$1
DNS_PLUGINS=$2

if [[ -z "${SNAP_ARCH}" ]]; then
    echo "You need to specify the target architecture"
    exit 1
fi

if [[ -z "${DNS_PLUGINS}" ]]; then
    echo "You need to specify the DNS plugins"
    exit 1
fi

if [[ "${DNS_PLUGINS}" = "ALL" ]]; then
    DNS_PLUGINS=$(find . -maxdepth 1 -type d -name "certbot-dns-*" -exec basename {} \; | paste -sd "," -)
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CERTBOT_DIR="$(dirname "$(dirname "${DIR}")")"

# shellcheck source=common.sh
source "${DIR}/common.sh"

RegisterQemuHandlers
ResolveArch "${SNAP_ARCH}"

pushd "${DIR}/packages"
"${CERTBOT_DIR}/tools/simple_http_server.py" 8080 >/dev/null 2>&1 &
HTTP_SERVER_PID="$!"
popd

function cleanup() {
    kill "${HTTP_SERVER_PID}"
}

trap cleanup EXIT

SCRIPT=$(mktemp /tmp/script.XXXXXX.sh)
chmod +x "${SCRIPT}"

SNAP_CONSTRAINTS=$(mktemp /tmp/snap-constraints.XXXXXX.txt)
python3 tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt | grep -v python-augeas > "${SNAP_CONSTRAINTS}"

cat << "EOF" >> "${SCRIPT}"
#!/bin/bash
set -ex
IFS=","
for DNS_PLUGIN in ${DNS_PLUGINS}; do
  pushd "${DNS_PLUGIN}"
  cp /snap-constraints.txt .
  snapcraft
  popd
done
EOF

docker run \
  --rm \
  --net=host \
  -v "${CERTBOT_DIR}:/certbot" \
  -v "${SCRIPT}:/script.sh" \
  -v "${SNAP_CONSTRAINTS}:/snap-constraints.txt" \
  -w "/certbot" \
  -e "DNS_PLUGINS=${DNS_PLUGINS}" \
  -e "PIP_EXTRA_INDEX_URL=http://localhost:8080" \
  "adferrand/snapcraft:${DOCKER_ARCH}-stable" \
  /script.sh
