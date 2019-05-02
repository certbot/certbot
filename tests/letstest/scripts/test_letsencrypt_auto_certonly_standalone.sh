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

# Create a venv-like layout at the old virtual environment path to test that a
# symlink is properly created when letsencrypt-auto runs.
HOME=${HOME:-~root}
XDG_DATA_HOME=${XDG_DATA_HOME:-~/.local/share}
OLD_VENV_BIN="$XDG_DATA_HOME/letsencrypt/bin"
mkdir -p "$OLD_VENV_BIN"
touch "$OLD_VENV_BIN/letsencrypt"

letsencrypt-auto certonly --no-self-upgrade -v --standalone --debug \
                   --text --agree-dev-preview --agree-tos \
                   --renew-by-default --redirect \
                   --register-unsafely-without-email \
                   --domain $PUBLIC_HOSTNAME --server $BOULDER_URL

if [ "$(tools/readlink.py ${XDG_DATA_HOME:-~/.local/share}/letsencrypt)" != "/opt/eff.org/certbot/venv" ]; then
    echo symlink from old venv path not properly created!
    exit 1
fi

if ! letsencrypt-auto --help --no-self-upgrade | grep -F "letsencrypt-auto [SUBCOMMAND]"; then
    echo "letsencrypt-auto not included in help output!"
    exit 1
fi

OUTPUT=$(letsencrypt-auto --install-only --no-self-upgrade --quiet 2>&1)
if [ -n "$OUTPUT" ]; then
    echo letsencrypt-auto produced unexpected output!
    exit 1
fi
