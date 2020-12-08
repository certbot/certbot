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

# Since certbot-auto is deprecated, we expect certbot-auto to error and
# refuse to install Certbot.
set +o pipefail
if ! letsencrypt-auto --debug --version | grep "Certbot cannot be installed."; then
    echo "letsencrypt-auto didn't report being uninstallable."
    exit 1
fi
if [ ${PIPESTATUS[0]} != 1 ]; then
    echo "letsencrypt-auto didn't exit with status 1 as expected"
    exit 1
fi
