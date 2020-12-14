#!/bin/sh -xe

cd letsencrypt

BOOTSTRAP_SCRIPT="tests/letstest/scripts/bootstrap_os_packages.sh"
VENV_PATH=venv3

# install OS packages
sudo $BOOTSTRAP_SCRIPT

# setup venv
# We strip the hashes because the venv creation script includes unhashed
# constraints in the commands given to pip and the mix of hashed and unhashed
# packages makes pip error out.
python3 tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt > requirements.txt
# We also strip out the requirement for enum34 because it cannot be installed
# in newer versions of Python 3, tools/strip_hashes.py removes the environment
# marker that'd normally prevent it from being installed, and this package is
# not needed for any OS tested here.
sed -i '/enum34/d' requirements.txt
CERTBOT_PIP_NO_BINARY=:all: tools/venv3.py --requirement requirements.txt
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
