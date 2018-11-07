#!/bin/sh -xe

LE_AUTO="letsencrypt/letsencrypt-auto-source/letsencrypt-auto"
LE_AUTO="$LE_AUTO --debug --no-self-upgrade --non-interactive"
MODULES="acme certbot certbot_apache certbot_nginx"
VENV_NAME=venv

# *-auto respects VENV_PATH
$LE_AUTO --os-packages-only
LE_AUTO_SUDO="" VENV_PATH="$VENV_NAME" $LE_AUTO --no-bootstrap --version
. $VENV_NAME/bin/activate

# change to an empty directory to ensure CWD doesn't affect tests
cd $(mktemp -d)
pip install pytest==3.2.5

for module in $MODULES ; do
    echo testing $module
    pytest -v --pyargs $module
done
