#!/bin/bash -x

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL
# are dynamically set at execution

# run certbot-apache2 via letsencrypt-auto
cd letsencrypt

export SUDO=sudo
if [ -f /etc/debian_version ] ; then
  echo "Bootstrapping dependencies for Debian-based OSes..."
  $SUDO bootstrap/_deb_common.sh
elif [ -f /etc/redhat-release ] ; then
  echo "Bootstrapping dependencies for RedHat-based OSes..."
  $SUDO bootstrap/_rpm_common.sh
else
  echo "Don't have bootstrapping for this OS!"
  exit 1
fi

bootstrap/dev/venv.sh
sudo venv/bin/certbot certonly --debug --standalone -t --agree-dev-preview --agree-tos \
                   --renew-by-default --redirect --register-unsafely-without-email \
                   --domain $PUBLIC_HOSTNAME --server $BOULDER_URL -v
if [ $? -ne 0 ] ; then
    FAIL=1
fi

if [ "$OS_TYPE" = "ubuntu" ] ; then
    venv/bin/tox -e apacheconftest
else
    echo Not running hackish apache tests on $OS_TYPE
fi

if [ $? -ne 0 ] ; then
    FAIL=1
fi

sudo venv/bin/certbot renew --renew-by-default

if [ $? -ne 0 ] ; then
    FAIL=1
fi


ls /etc/letsencrypt/archive/$PUBLIC_HOSTNAME | grep -q 2.pem

if [ $? -ne 0 ] ; then
    FAIL=1
fi

# return error if any of the subtests failed
if [ "$FAIL" = 1 ] ; then
    exit 1
fi
