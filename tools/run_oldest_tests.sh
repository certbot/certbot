#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd "${DIR}/../" || exit 1

function cleanup() {
  rm -f "${SCRIPT}"
  popd
}

trap cleanup EXIT

SCRIPT=$(mktemp /tmp/test-script.XXXXXX)
chmod +x "${SCRIPT}"

cat << "EOF" >> "${SCRIPT}"
#!/bin/bash
set -e
apt-get update
apt-get install -y --no-install-recommends \
    git \
    gcc \
    libaugeas0 \
    libssl-dev \
    libffi-dev \
    ca-certificates \
    nginx-light \
    openssl \
    curl \
    make
sh <(curl -fsSL https://get.docker.com)
curl -fsSL https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz | tar xvz
cd Python-2.7.18/
./configure --prefix /usr/local/lib/python --enable-ipv6
make -j2 && make install
cd .. && rm -rf Python-2.7.18 && cd certbot
/usr/local/lib/python/bin/python -m ensurepip
/usr/local/lib/python/bin/python -m pip install tox
/usr/local/lib/python/bin/python -m tox
EOF

docker run \
  --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${PWD}:${PWD}" -v "${SCRIPT}:/script.sh" \
  -v /tmp:/tmp \
  -e TOXENV \
  -e ACME_SERVER \
  -e PYTEST_ADDOPTS \
  -w "${PWD}" \
  --network=host \
  ubuntu:14.04 \
  /script.sh
