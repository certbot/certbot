#!/bin/bash -x

# >>>> only tested on Ubuntu 14.04LTS <<<<

# non-interactive install of mariadb and other dependencies
export DEBIAN_FRONTEND=noninteractive
sudo debconf-set-selections <<< 'mariadb-server mysql-server/root_password password PASS'
sudo debconf-set-selections <<< 'mariadb-server mysql-server/root_password_again password PASS'
apt-get -y --no-upgrade install git make libltdl3-dev mariadb-server rabbitmq-server
sudo mysql -uroot -pPASS -e "SET PASSWORD = PASSWORD(\'\');"

# install go
wget https://storage.googleapis.com/golang/go1.5.1.linux-amd64.tar.gz
tar xzvf go1.5.1.linux-amd64.tar.gz
mkdir gocode
echo "export GOROOT=/home/ubuntu/go \n\
      export GOPATH=/home/ubuntu/gocode\n\
      export PATH=/home/ubuntu/go/bin:/home/ubuntu/gocode/bin:$PATH" >> .bashrc

# install boulder and its go dependencies
go get -d github.com/letsencrypt/boulder/...
cd $GOPATH/src/github.com/letsencrypt/boulder
wget https://github.com/jsha/boulder-tools/raw/master/goose.gz
mkdir $GOPATH/bin
zcat goose.gz > $GOPATH/bin/goose
chmod +x $GOPATH/bin/goose
./test/create_db.sh
go get github.com/jsha/listenbuddy
