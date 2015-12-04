#!/bin/bash -x

#install apache2 on apt systems
# debian doesn't come with curl
sudo apt-get update
sudo apt-get -y --no-upgrade install apache2 curl

# $BOULDER_URL is dynamically set at execution
# fetch instance data from EC2 metadata service
public_host=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-hostname)
public_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-ipv4)
private_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/local-ipv4)

# For apache 2.4, set up ServerName
sudo sed -i '/ServerName/ s/#ServerName/ServerName/' \
     /etc/apache2/sites-available/000-default.conf
sudo sed -i '/ServerName/ s/www.example.com/'$public_host'/' \
    /etc/apache2/sites-available/000-default.conf

# run letsencrypt-apache2 via letsencrypt-auto
cd letsencrypt
./letsencrypt-auto -v --debug --text --agree-dev-preview --agree-tos \
                   --renew-by-default --redirect --register-unsafely-without-email \
                   --domain $public_host --server $BOULDER_URL
