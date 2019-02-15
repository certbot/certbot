#!/bin/sh -xe

cd letsencrypt
./certbot-auto --os-packages-only -n --debug

PLUGINS="certbot-apache certbot-nginx"
PYTHON=$(command -v python2.7 || command -v python27 || command -v python2 || command -v python)
TEMP_DIR=$(mktemp -d)
VERSION=$(letsencrypt-auto-source/version.py)
export VENV_ARGS="-p $PYTHON"

# setup venv
tools/_venv_common.py --requirement letsencrypt-auto-source/pieces/dependency-requirements.txt
. ./venv/bin/activate
# pytest is needed to run tests on some of our packages so we install a pinned version here.
tools/pip_install.py pytest

# build sdists
for pkg_dir in acme . $PLUGINS; do
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
