#!/bin/bash -x
set -eo pipefail

# $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL are dynamically set at execution

# with curl, instance metadata available from EC2 metadata service:
#public_host=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-hostname)
#public_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-ipv4)
#private_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/local-ipv4)

cd letsencrypt
LE_AUTO_DIR="/usr/local/bin"
LE_AUTO_PATH="$LE_AUTO_DIR/letsencrypt-auto"
sudo cp letsencrypt-auto-source/letsencrypt-auto "$LE_AUTO_PATH"
sudo chown root "$LE_AUTO_PATH"
sudo chmod 0755 "$LE_AUTO_PATH"
export PATH="$LE_AUTO_DIR:$PATH"

letsencrypt-auto --os-packages-only --debug --version

# This script sets the environment variables PYTHON_NAME, VENV_PATH, and
# VENV_SCRIPT based on the version of Python available on the system. For
# instance, Fedora uses Python 3 and Python 2 is not installed.
. tests/letstest/scripts/set_python_envvars.sh

# Create a venv-like layout at the old virtual environment path to test that a
# symlink is properly created when letsencrypt-auto runs.
HOME=${HOME:-~root}
XDG_DATA_HOME=${XDG_DATA_HOME:-~/.local/share}
OLD_VENV_BIN="$XDG_DATA_HOME/letsencrypt/bin"
mkdir -p "$OLD_VENV_BIN"
touch "$OLD_VENV_BIN/letsencrypt"

letsencrypt-auto certonly --no-self-upgrade -v --standalone --debug \
                   --text --agree-tos \
                   --renew-by-default --redirect \
                   --register-unsafely-without-email \
                   --domain $PUBLIC_HOSTNAME --server $BOULDER_URL

LINK_PATH=$("$PYTHON_NAME" tools/readlink.py ${XDG_DATA_HOME:-~/.local/share}/letsencrypt)
if [ "$LINK_PATH" != "/opt/eff.org/certbot/venv" ]; then
    echo symlink from old venv path not properly created!
    exit 1
fi

if ! letsencrypt-auto --help --no-self-upgrade | grep -F "letsencrypt-auto [SUBCOMMAND]"; then
    echo "letsencrypt-auto not included in help output!"
    exit 1
fi

OUTPUT_LEN=$(letsencrypt-auto --install-only --no-self-upgrade --quiet 2>&1 | wc -c)
if [ "$OUTPUT_LEN" != 0 ]; then
    echo letsencrypt-auto produced unexpected output!
    exit 1
fi
