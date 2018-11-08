#!/bin/bash -x
XDG_DATA_HOME=${XDG_DATA_HOME:-~/.local/share}
VENV_NAME="venv"
# The path to the letsencrypt-auto script.  Everything that uses these might
# at some point be inlined...
LEA_PATH=./letsencrypt/
VENV_PATH=${LEA_PATH/$VENV_NAME}
VENV_BIN=${VENV_PATH}/bin


# virtualenv call is not idempotent: it overwrites pip upgraded in
# later steps, causing "ImportError: cannot import name unpack_url"

"$LEA_PATH/letsencrypt-auto" --os-packages-only

cd letsencrypt
python tools/venv.py
venv/bin/tox -e py27
