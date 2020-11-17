#!/bin/sh -xe
#
# This script is useful for testing that the packages we've built for a release
# work on a variety of systems. For an example of the kinds of problems that
# can occur, see https://github.com/certbot/certbot/issues/3455.

REPO_ROOT="letsencrypt"
LE_AUTO="$REPO_ROOT/letsencrypt-auto-source/letsencrypt-auto"
LE_AUTO="$LE_AUTO --debug --no-self-upgrade --non-interactive"
MODULES="acme certbot certbot-apache certbot-nginx"
PIP_INSTALL="tools/pip_install.py"
VENV_NAME=venv3
BOOTSTRAP_SCRIPT="$REPO_ROOT/tests/letstest/scripts/bootstrap_os_packages.sh"
VENV_SCRIPT="tools/venv3.py"

sudo $BOOTSTRAP_SCRIPT

if command -v python && [ $(python -V 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//') -eq 26 ]; then
  # RHEL/CentOS 6 will need a special treatment, so we need to detect that environment
  # Enable the SCL Python 3.6 installed by letsencrypt-auto bootstrap
  PATH="/opt/rh/rh-python36/root/usr/bin:$PATH"
fi

cd $REPO_ROOT
$VENV_SCRIPT
. $VENV_NAME/bin/activate
"$PIP_INSTALL" pytest

# To run tests that aren't packaged in modules, run pytest
# from the repo root. The directory structure should still
# cause the installed packages to be tested while using
# the tests available in the subdirectories.

for module in $MODULES ; do
    echo testing $module
    pytest -v $module
done
