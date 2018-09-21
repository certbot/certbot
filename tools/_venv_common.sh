#!/bin/sh -xe

VENV_NAME=${VENV_NAME:-venv}

# .egg-info directories tend to cause bizarre problems (e.g. `pip -e
# .` might unexpectedly install letshelp-certbot only, in case
# `python letshelp-certbot/setup.py build` has been called
# earlier)
rm -rf *.egg-info

# virtualenv setup is NOT idempotent: shutil.Error:
# `/home/jakub/dev/letsencrypt/letsencrypt/venv/bin/python2` and
# `venv/bin/python2` are the same file
mv $VENV_NAME "$VENV_NAME.$(date +%s).bak" || true
virtualenv --no-site-packages --setuptools $VENV_NAME $VENV_ARGS
. ./$VENV_NAME/bin/activate

# Use pipstrap to update Python packaging tools to only update to a well tested
# version and to work around https://github.com/pypa/pip/issues/4817 on older
# systems.
python letsencrypt-auto-source/pieces/pipstrap.py
./tools/pip_install.sh "$@"

set +x
echo "Please run the following command to activate developer environment:"
echo "source $VENV_NAME/bin/activate"
