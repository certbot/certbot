#!/bin/sh -xe

cd letsencrypt

BOOTSTRAP_SCRIPT="tests/letstest/scripts/bootstrap_os_packages.sh"
VENV_PATH=venv3

# install OS packages
sudo $BOOTSTRAP_SCRIPT

if command -v python && [ $(python -V 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//') -eq 26 ]; then
  # RHEL/CentOS 6 will need a special treatment, so we need to detect that environment
  # Enable the SCL Python 3.6 installed by letsencrypt-auto bootstrap
  PATH="/opt/rh/rh-python36/root/usr/bin:$PATH"
fi

# setup venv
CERTBOT_PIP_NO_BINARY=:all: tools/venv3.py --requirement letsencrypt-auto-source/pieces/dependency-requirements.txt
. "$VENV_PATH/bin/activate"
# pytest is needed to run tests on some of our packages so we install a pinned version here.
tools/pip_install.py pytest

PLUGINS="certbot-apache certbot-nginx"
TEMP_DIR=$(mktemp -d)

# build sdists
for pkg_dir in acme certbot $PLUGINS; do
    cd $pkg_dir
    python setup.py clean
    rm -rf build dist
    python setup.py sdist
    mv dist/* $TEMP_DIR
    cd -
done

VERSION=$(python letsencrypt-auto-source/version.py)
# test sdists
cd $TEMP_DIR
for pkg in acme certbot $PLUGINS; do
    tar -xvf "$pkg-$VERSION.tar.gz"
    cd "$pkg-$VERSION"
    python setup.py build
    python -m pytest
    python setup.py install
    cd -
done
