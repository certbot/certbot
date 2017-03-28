#!/bin/bash -x

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

# we have to jump through some hoops to cope with relative paths in renewal
# conf files ...
# 1. be in the right directory
cd tests/letstest/testdata/

# 2. refer to the config with the same level of relativity that it itself
# contains :/
OUT=`letsencrypt-auto certificates --config-dir sample-config -v --no-self-upgrade`
TEST_CERTS=`echo "$OUT" | grep TEST_CERT | wc -l`
REVOKED=`echo "$OUT" | grep REVOKED | wc -l`

if [ "$TEST_CERTS" != 2 ] ; then
    echo "Did not find two test certs as expected ($TEST_CERTS)"
    exit 1
fi

if [ "$REVOKED" != 1 ] ; then
    echo "Did not find one revoked cert as expected ($REVOKED)"
    exit 1
fi
