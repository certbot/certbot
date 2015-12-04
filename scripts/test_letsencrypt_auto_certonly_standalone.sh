#!/bin/bash -x

# $BOULDER_URL is dynamically set at execution
# fetch instance data from EC2 metadata service
public_host=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-hostname)
public_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-ipv4)
private_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/local-ipv4)

cd letsencrypt
./letsencrypt-auto certonly -v --standalone --debug \
                   --text --agree-dev-preview --agree-tos \
                   --renew-by-default --redirect \
                   --register-unsafely-without-email \
                   --domain $public_host --server $BOULDER_URL
