#!/bin/bash
# Cross-compile cryptography and cffi native wheels for arm64 and armhf architectures,
# on the versions required by the current pinning of Certbot dependencies.
# Wheels are stored in snap/local/packages folder to speed up cross-compilation of Certbot snap.
set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TARGET_ARCHS="arm64 armhf"

rm -f "${DIR}/packages/"*

# shellcheck source=common.sh
source "${DIR}/common.sh"

RegisterQemuHandlers

tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt > "${DIR}/snap-constraints.txt"
for ARCH in ${TARGET_ARCHS}; do
    QEMU_ARCH="$(GetQemuArch "${ARCH}")"
    DownloadQemuStatic "${QEMU_ARCH}" "${DIR}"

    docker run \
        --rm \
        -v "${DIR}/qemu-${QEMU_ARCH}-static:/usr/bin/qemu-${QEMU_ARCH}-static" \
        -v "${DIR}:/workspace" \
        -w "/workspace" \
        "$(GetDockerArch "${ARCH}")/ubuntu:18.04" \
        sh -c "\
   apt-get update \
&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-venv python3-dev libffi-dev libssl-dev gcc \
&& mkdir -p /build \
&& python3 -m venv /build/venv \
&& /build/venv/bin/pip install wheel \
&& /build/venv/bin/pip wheel cryptography cffi -c snap-constraints.txt -w /build \
&& mkdir -p /workspace/packages \
&& mv /build/cryptography* /build/cffi* /workspace/packages \
&& chmod -R 777 /workspace/packages
"
done
