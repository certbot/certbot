#!/bin/sh -xe

cd letsencrypt

BOOTSTRAP_SCRIPT="tests/letstest/scripts/bootstrap_os_packages.sh"
VENV_PATH=venv

# install OS packages
sudo $BOOTSTRAP_SCRIPT

# setup venv
# We strip the hashes because the venv creation script includes unhashed
# constraints in the commands given to pip and the mix of hashed and unhashed
# packages makes pip error out.
python3 tools/strip_hashes.py tools/certbot_constraints.txt > requirements.txt

# We pin cryptography to 3.1.1 specifically for CentOS 7 / RHEL 7 because these systems ship
# only with OpenSSL 1.0.2, and this OpenSSL version support has been dropped on cryptography>=3.2.
# Using this old version of OpenSSL would break the cryptography wheel build.
if [ -f /etc/redhat-release ] && [ "$(. /etc/os-release 2> /dev/null && echo "$VERSION_ID")" -eq 7 ]; then
  sed -i 's|cryptography==.*|cryptography==3.1.1|g' requirements.txt
fi

CERTBOT_PIP_NO_BINARY=:all: tools/venv.py --requirement requirements.txt
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
