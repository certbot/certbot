#!/bin/sh -xe

cd letsencrypt

BOOTSTRAP_SCRIPT="letstest/scripts/bootstrap_os_packages.sh"
VENV_PATH=venv

# install OS packages
. $BOOTSTRAP_SCRIPT

# setup venv
python3 -m venv $VENV_PATH
$VENV_PATH/bin/python3 tools/pipstrap.py
. "$VENV_PATH/bin/activate"
# pytest is needed to run tests on our packages so we install a pinned version here.
tools/pip_install.py pytest

# setup constraints
TEMP_DIR=$(mktemp -d)
CONSTRAINTS="$TEMP_DIR/constraints.txt"
cp tools/requirements.txt "$CONSTRAINTS"


PLUGINS="certbot-apache certbot-nginx"
# build sdists
for pkg_dir in acme certbot $PLUGINS; do
    cd $pkg_dir
    python setup.py clean
    rm -rf build dist
    python setup.py sdist
    mv dist/* $TEMP_DIR
    cd -
done

VERSION=$(python letstest/scripts/version.py)
# test sdists
cd $TEMP_DIR
for pkg in acme certbot $PLUGINS; do
    tar -xvf "$pkg-$VERSION.tar.gz"
    cd "$pkg-$VERSION"
    PIP_CONSTRAINT=../constraints.txt PIP_NO_BINARY=:all: pip install .
    python -m pytest
    cd -
done
