#!/bin/bash

set -ex

apt-get -y install lsb-release net-tools wget python nginx

wget https://github.com/docker/compose/releases/download/1.15.0-rc1/docker-compose-Linux-x86_64 -O /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

cat << EOF > /usr/local/bin/coverage
#!/bin/bash -xe

if [ "\$1" != "run" ]; then
    exit 0;
fi

"\${@:7}"
EOF
chmod +x /usr/local/bin/coverage

certbot_version=$(certbot --version 2>&1 | grep "^certbot" | cut -d " " -f 2)

cd parts/certbot/src

tests/boulder-fetch.sh
until curl http://localhost:4000/directory 2>/dev/null; do
  echo waiting for boulder
  sleep 1
done
# Not needed under Travis Trusty?
#sed -i "s/'1.3.6.1.5.5.7.1.24'/-e '1.3.6.1.5.5.7.1.24' -e 'status_request'/g" tests/certbot-boulder-integration.sh
tests/boulder-integration.sh

echo "Success!"
