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
    python-dev \
    python-pip \
    git \
    gcc \
    libaugeas0 \
    libssl-dev \
    libffi-dev \
    ca-certificates \
    nginx-light \
    openssl \
    curl \
    software-properties-common
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 5BB92C09DB82666C
add-apt-repository ppa:fkrull/deadsnakes-python2.7
apt-get update
apt-get upgrade -y
sh <(curl -fsSL https://get.docker.com)
python -m pip install --upgrade pip virtualenv wheel
python -m pip install tox
python -m tox
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
