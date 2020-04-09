#!/bin/bash
set -ex

sudo /snap/bin/lxd.migrate -yes
sudo /snap/bin/lxd waitready
sudo /snap/bin/lxd init --auto
tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt > constraints.txt
sudo snapcraft --use-lxd
sudo snap install --dangerous --classic *.snap
