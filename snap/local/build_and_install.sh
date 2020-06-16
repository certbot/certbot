#!/bin/bash
set -ex

if [[ -z "$TRAVIS" ]]; then
    echo "This script makes global changes to the system it is run on so should only be run in CI."
    exit 1
fi

# Add the current user to the lxd group so they can run `snapcraft --use-lxd`
# without sudo since running the command without sudo is required by newer
# versions of snapcraft.
sudo usermod -aG lxd "$USER"
sudo /snap/bin/lxd.migrate -yes
sudo /snap/bin/lxd waitready
sudo /snap/bin/lxd init --auto
tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt > snap-constraints.txt
# Run snapcraft with the lxd group since it has not been added to the current
# shell.
sg lxd -c 'snapcraft --use-lxd'
sudo snap install --dangerous --classic *.snap
