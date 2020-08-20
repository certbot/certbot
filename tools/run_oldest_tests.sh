#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd "${DIR}/../"

function cleanup() {
  rm -f "${DOCKERFILE}"
  popd
}

trap cleanup EXIT

DOCKERFILE=$(mktemp /tmp/Dockerfile.XXXXXX)

cat << "EOF" >> "${DOCKERFILE}"
FROM ubuntu:16.04
COPY pipstrap.py /tmp/pipstrap.py
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python-dev python-pip python-setuptools \
        gcc libaugeas0 libssl-dev libffi-dev \
        git ca-certificates nginx-light openssl curl \
 && curl -fsSL https://get.docker.com | bash /dev/stdin \
 && python /tmp/pipstrap.py \
 && python -m pip install tox \
 && rm -rf /var/lib/apt/lists/*
EOF

docker build -f "${DOCKERFILE}" -t oldest-worker ./letsencrypt-auto-source/pieces
docker run --rm --network=host -w "${PWD}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${PWD}:${PWD}" -v /tmp:/tmp \
  -e TOXENV -e ACME_SERVER -e PYTEST_ADDOPTS \
  oldest-worker python -m tox
