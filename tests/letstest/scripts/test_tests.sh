#!/bin/sh -xe
#
# This script is useful for testing that the packages we've built for a release
# work on a variety of systems. For an example of the kinds of problems that
# can occur, see https://github.com/certbot/certbot/issues/3455.

REPO_ROOT="letsencrypt"
LE_AUTO="$REPO_ROOT/letsencrypt-auto-source/letsencrypt-auto"
LE_AUTO="$LE_AUTO --debug --no-self-upgrade --non-interactive"
MODULES="acme certbot certbot-apache certbot-nginx"
PIP_INSTALL="$REPO_ROOT/tools/pip_install.py"
VENV_NAME=venv

# *-auto respects VENV_PATH
$LE_AUTO --os-packages-only
LE_AUTO_SUDO="" VENV_PATH="$VENV_NAME" $LE_AUTO --no-bootstrap --version
. $VENV_NAME/bin/activate
"$PIP_INSTALL" pytest

# To run tests that aren't packaged in modules, run pytest
# from the repo root. The directory structure should still
# cause the installed packages to be tested while using
# the tests available in the subdirectories.
cd $REPO_ROOT

for module in $MODULES ; do
    echo testing $module
    pytest -v $module
done
