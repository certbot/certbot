#!/bin/bash -x

# Configures and Launches Boulder Server installed on
# us-east-1 ami-072a9534772bec854 bouldertestserver3 (boulder commit b24fe7c3ea4)

# fetch instance data from EC2 metadata service
public_host=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-hostname)
public_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-ipv4)
private_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/local-ipv4)

# set to public DNS resolver
resolver_ip=8.8.8.8
resolver=$resolver_ip':53'

# modifies integration testing boulder setup for local AWS VPC network
# connections instead of localhost
cd $GOPATH/src/github.com/letsencrypt/boulder
# change test ports to real
sed -i '/httpPort/ s/5002/80/' ./test/config/va.json
sed -i '/httpsPort/ s/5001/443/' ./test/config/va.json
sed -i '/tlsPort/ s/5001/443/' ./test/config/va.json
# set dns resolver
sed -i 's/"127.0.0.1:8053",/"'$resolver'"/' ./test/config/va.json
sed -i 's/"127.0.0.1:8054"//' ./test/config/va.json
