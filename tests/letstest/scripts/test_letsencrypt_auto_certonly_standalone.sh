#!/bin/bash -x
set -eo pipefail

# $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL are dynamically set at execution

# with curl, instance metadata available from EC2 metadata service:
#public_host=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-hostname)
#public_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-ipv4)
#private_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/local-ipv4)

cd letsencrypt
export PATH="$PWD/letsencrypt-auto-source:$PATH"
letsencrypt-auto --os-packages-only --debug --version
letsencrypt-auto certonly --no-self-upgrade -v --standalone --debug \
                   --text --agree-dev-preview --agree-tos \
                   --renew-by-default --redirect \
                   --register-unsafely-without-email \
                   --domain $PUBLIC_HOSTNAME --server $BOULDER_URL

if ! letsencrypt-auto --help --no-self-upgrade | grep -F "letsencrypt-auto [SUBCOMMAND]"; then
    echo "letsencrypt-auto not included in help output!"
    exit 1
fi
