#!/bin/sh -xe

MODULES="acme certbot certbot_apache certbot_nginx"
VENV_NAME=venv

# *-auto respects VENV_PATH
VENV_PATH=$VENV_NAME letsencrypt/certbot-auto --debug --non-interactive --version
. $VENV_NAME/bin/activate

# change to an empty directory to ensure CWD doesn't affect tests
cd $(mktemp -d)
pip install nose

for module in $MODULES ; do
    echo testing $module
    nosetests -v $module
done
