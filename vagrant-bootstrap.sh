#!/usr/bin/env bash

export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" postfix
cat > /etc/hosts <<<EOF
192.168.33.5 sender sender.example.com
192.168.33.7 valid valid-example-recipient.com
EOF
