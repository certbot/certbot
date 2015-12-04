#!/bin/bash -x

# Configures and Launches Boulder Server installed on
# us-east-1 ami-5f490b35 bouldertestserver (boulder commit 8b433f54dab)

# fetch instance data from EC2 metadata service
public_host=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-hostname)
public_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-ipv4)
private_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/local-ipv4)

# get local DNS resolver for VPC
resolver_ip=$(grep nameserver /etc/resolv.conf |cut -d" " -f2 |head -1)
resolver=$resolver_ip':53'

# modifies integration testing boulder setup for local AWS VPC network
# connections instead of localhost
cd $GOPATH/src/github.com/letsencrypt/boulder
# configure boulder to receive outside connection on 4000
sed -i '/listenAddress/ s/127.0.0.1:4000/'$private_ip':4000/' ./test/boulder-config.json
sed -i '/baseURL/ s/127.0.0.1:4000/'$private_ip':4000/' ./test/boulder-config.json
# change test ports to real
sed -i '/httpPort/ s/5002/80/' ./test/boulder-config.json
sed -i '/httpsPort/ s/5001/443/' ./test/boulder-config.json
sed -i '/tlsPort/ s/5001/443/' ./test/boulder-config.json
# set local dns resolver
sed -i '/dnsResolver/ s/127.0.0.1:8053/'$resolver'/' ./test/boulder-config.json

# start rabbitMQ
#go run cmd/rabbitmq-setup/main.go -server amqp://localhost
# start acme services
#nohup ./start.py >& /dev/null < /dev/null &
#./start.py
