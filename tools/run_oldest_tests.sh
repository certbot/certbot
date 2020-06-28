#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd "${DIR}/../" || exit 1

function cleanup() {
  rm -f "${SCRIPT}"
  popd
}

trap cleanup EXIT

DOCKERFILE=$(mktemp /tmp/Dockerfile.XXXXXX)

cat << "EOF" >> "${DOCKERFILE}"
FROM ubuntu:14.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python-dev python-pip git gcc libaugeas0 libssl-dev libffi-dev \
        ca-certificates nginx-light openssl curl software-properties-common \
 && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 5BB92C09DB82666C \
 && add-apt-repository ppa:fkrull/deadsnakes-python2.7 \
 && apt-get update \
 && apt-get upgrade -y \
 && curl -fsSL https://get.docker.com | bash /dev/stdin \
 && python -m pip install --upgrade pip virtualenv wheel \
 && python -m pip install tox \
 && rm -rf /var/lib/apt/lists/*
EOF

docker build -f "${DOCKERFILE}" -t oldest-worker "${DIR}"
docker run --rm --network=host -w "${PWD}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${PWD}:${PWD}" -v "${SCRIPT}:/script.sh" \
  -v /tmp:/tmp \
  -e TOXENV -e ACME_SERVER -e PYTEST_ADDOPTS \
  oldest-worker python -m tox
