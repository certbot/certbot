#!/bin/sh -xe

cd letsencrypt

BOOTSTRAP_SCRIPT="tests/letstest/scripts/bootstrap_os_packages.sh"
VENV_PATH=venv3

# bootstrap and setup venv
sudo $BOOTSTRAP_SCRIPT . "CERTBOT_PIP_NO_BINARY=:all: $VENV_SCRIPT --requirement letsencrypt-auto-source/pieces/dependency-requirements.txt"
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

# test sdists
cd $TEMP_DIR
for pkg in acme certbot $PLUGINS; do
    tar -xvf "$pkg-$VERSION.tar.gz"
    cd "$pkg-$VERSION"
    python setup.py build
    python setup.py test
    python setup.py install
    cd -
done
