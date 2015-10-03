#!/bin/sh

#Check Homebrew
if ! hash brew 2>/dev/null; then
    echo "Homebrew Not Installed\nDownloading..."
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
fi

brew install libtool mariadb rabbitmq coreutils go

mysql.server start

rabbit_pid=`ps | grep rabbitmq | grep -v grep | awk '{ print $1}'`
if [ -n "$rabbit_pid" ]; then
  echo "RabbitMQ already running"
else
  rabbitmq-server &
fi

hosts_entry=`cat /etc/hosts | grep "127.0.0.1 le.wtf"`
if [ -z "$hosts_entry" ]; then
  echo "Adding hosts entry for le.wtf..."
  sudo sh -c "echo 127.0.0.1 le.wtf >> /etc/hosts"
fi

./tests/boulder-start.sh
