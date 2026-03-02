#!/bin/bash -ex

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL
# are dynamically set at execution

if [ "$OS_TYPE" = "ubuntu" ]
then
    CONFFILE=/etc/apache2/sites-available/000-default.conf
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y --no-upgrade install apache2 curl
    # For apache 2.4, set up ServerName
    sudo sed -i '/ServerName/ s/#ServerName/ServerName/' $CONFFILE
    sudo sed -i '/ServerName/ s/www.example.com/'$PUBLIC_HOSTNAME'/' $CONFFILE
elif [ "$OS_TYPE" = "centos" ]
then
    CONFFILE=/etc/httpd/conf/httpd.conf
    sudo setenforce 0 || true #disable selinux
    sudo yum -y install httpd mod_ssl
    sudo service httpd start
    sudo mkdir -p /var/www/$PUBLIC_HOSTNAME/public_html
    sudo chmod -R oug+rwx /var/www
    sudo chmod -R oug+rw /etc/httpd
    sudo echo '<html><head><title>foo</title></head><body>bar</body></html>' > /var/www/$PUBLIC_HOSTNAME/public_html/index.html
    sudo mkdir /etc/httpd/sites-available #certbot requires this...
    sudo mkdir /etc/httpd/sites-enabled #certbot requires this...
    #sudo echo "IncludeOptional sites-enabled/*.conf" >> /etc/httpd/conf/httpd.conf
    sudo echo """
<VirtualHost *:80>
    ServerName $PUBLIC_HOSTNAME
    DocumentRoot /var/www/$PUBLIC_HOSTNAME/public_html
    ErrorLog /var/www/$PUBLIC_HOSTNAME/error.log
    CustomLog /var/www/$PUBLIC_HOSTNAME/requests.log combined
</VirtualHost>""" >> /etc/httpd/conf.d/$PUBLIC_HOSTNAME.conf
    #sudo cp /etc/httpd/sites-available/$PUBLIC_HOSTNAME.conf /etc/httpd/sites-enabled/
fi

# Run certbot-apache2.
cd letsencrypt

echo "Bootstrapping dependencies..."
sudo letstest/scripts/bootstrap_os_packages.sh

# Install pyenv
curl https://pyenv.run | bash
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init --path)"
eval "$(pyenv init -)"

# Install and configure Python
pyenv install 3.10
pyenv shell 3.10

tools/venv.py -e acme -e certbot -e certbot-apache -e certbot-ci tox
PEBBLE_LOGS="acme_server.log"
PEBBLE_URL="https://localhost:14000/dir"
# We configure Pebble to use port 80 for http-01 validation rather than an
# alternate port because:
#   1) It allows us to test with Apache configurations that are more realistic
#   and closer to the default configuration on various OSes.
#   2) As of writing this, Certbot's Apache plugin requires there to be an
#   existing virtual host for the port used for http-01 validation.
venv/bin/run_acme_server --http-01-port 80 > "${PEBBLE_LOGS}" 2>&1 &

DumpPebbleLogsOnFailure() {
    exit_status="$?"
    if [ "$exit_status" != 0 ] && [ -f "${PEBBLE_LOGS}" ] ; then
        echo "Pebble's logs were:"
        cat "${PEBBLE_LOGS}"
    fi
    exit "$exit_status"
}
trap DumpPebbleLogsOnFailure EXIT

for n in $(seq 1 150) ; do
    if curl --insecure "${PEBBLE_URL}" 2>/dev/null; then
        break
    else
        echo "waiting for pebble"
        sleep 1
    fi
done
if ! curl --insecure "${PEBBLE_URL}" 2>/dev/null; then
  echo "timed out waiting for pebble to start"
  DumpPebbleLogs
  exit 1
fi

sudo "venv/bin/certbot" -v --debug --text --agree-tos --no-verify-ssl \
                   --renew-by-default --redirect --register-unsafely-without-email \
                   --domain "${PUBLIC_HOSTNAME}" --server "${PEBBLE_URL}"

if ! grep -q SSLSessionTickets /etc/letsencrypt/options-ssl-apache.conf; then
    echo "modern TLS options were not used"
    exit 1
fi

if [ "$OS_TYPE" = "ubuntu" ] ; then
    export SERVER="${PEBBLE_URL}"
    "venv/bin/tox" -e apacheconftest
else
    echo Not running hackish apache tests on $OS_TYPE
fi
