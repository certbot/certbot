#!/bin/sh -xe

cd letsencrypt
letsencrypt-auto-source/letsencrypt-auto --install-only -n --debug

PLUGINS="certbot-apache certbot-nginx"
PYTHON_MAJOR_VERSION=$(/opt/eff.org/certbot/venv/bin/python --version 2>&1 | cut -d" " -f 2 | cut -d. -f1)
TEMP_DIR=$(mktemp -d)

if [ "$PYTHON_MAJOR_VERSION" = "3" ]; then
    # Some distros like Fedora may only have an executable named python3 installed.
    PYTHON_NAME="python3"
    VENV_PATH="venv3"
    VENV_SCRIPT="tools/venv3.py"
else
    PYTHON_NAME="python"
    VENV_SCRIPT="tools/venv.py"
    VENV_PATH="venv"
fi

VERSION=$("$PYTHON_NAME" letsencrypt-auto-source/version.py)

# setup venv
"$VENV_SCRIPT" --requirement letsencrypt-auto-source/pieces/dependency-requirements.txt
. "$VENV_PATH/bin/activate"
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
