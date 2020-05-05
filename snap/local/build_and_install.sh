#!/bin/bash
set -ex

if [[ -z "$TRAVIS" ]]; then
    echo "This script makes global changes to the system it is run on so should only be run in CI."
    exit 1
fi

sudo /snap/bin/lxd.migrate -yes
sudo /snap/bin/lxd waitready
sudo /snap/bin/lxd init --auto
tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt > constraints.txt
sudo snapcraft --use-lxd
sudo snap install --dangerous --classic *.snap
