#!/bin/bash -x

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL
# are dynamically set at execution

if [ "$OS_TYPE" = "ubuntu" ]
then
    CONFFILE=/etc/apache2/sites-available/000-default.conf
    sudo apt-get update
    sudo apt-get -y --no-upgrade install apache2 curl
    sudo apt-get -y install realpath # needed for test-apache-conf
    # For apache 2.4, set up ServerName
    sudo sed -i '/ServerName/ s/#ServerName/ServerName/' $CONFFILE
    sudo sed -i '/ServerName/ s/www.example.com/'$PUBLIC_HOSTNAME'/' $CONFFILE
    if [ $(python3 -V 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//') -lt 36 ]
    then
        # Upgrade python version using pyenv because py3.5 is deprecated
        # Don't upgrade if it's already 3.8 because pyenv doesn't work great on arm, and
        # our arm representative happens to be ubuntu20, which already has a perfectly
        # good version of python.
        sudo apt-get install -y make gcc build-essential libssl-dev zlib1g-dev libbz2-dev \
          libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
          xz-utils tk-dev libffi-dev liblzma-dev python-openssl git # pyenv deps
        curl https://pyenv.run | bash
        export PATH="~/.pyenv/bin:$PATH"
        pyenv init -
        pyenv virtualenv-init -
        pyenv install 3.8.5
        pyenv global 3.8.5
        # you do, in fact need to run these again, exactly like this.
        eval "$(pyenv init -)"
        eval "$(pyenv virtualenv-init -)"
    fi
elif [ "$OS_TYPE" = "centos" ]
then
    CONFFILE=/etc/httpd/conf/httpd.conf
    sudo setenforce 0 || true #disable selinux
    sudo yum -y install httpd
    sudo yum -y install nghttp2 || echo this is probably ok but see https://bugzilla.redhat.com/show_bug.cgi?id=1358875
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
sudo tests/letstest/scripts/bootstrap_os_packages.sh
if [ $? -ne 0 ] ; then
    exit 1
fi

tools/venv.py -e acme[dev] -e certbot[dev,docs] -e certbot-apache -e certbot-ci
PEBBLE_LOGS="acme_server.log"
PEBBLE_URL="https://localhost:14000/dir"
# We configure Pebble to use port 80 for http-01 validation rather than an
# alternate port because:
#   1) It allows us to test with Apache configurations that are more realistic
#   and closer to the default configuration on various OSes.
#   2) As of writing this, Certbot's Apache plugin requires there to be an
#   existing virtual host for the port used for http-01 validation.
venv/bin/run_acme_server --http-01-port 80 > "${PEBBLE_LOGS}" 2>&1 &

DumpPebbleLogs() {
    if [ -f "${PEBBLE_LOGS}" ] ; then
        echo "Pebble's logs were:"
        cat "${PEBBLE_LOGS}"
    fi
}

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
if [ $? -ne 0 ] ; then
    FAIL=1
fi

# Check that ssl_module detection is working on various systems
if [ "$OS_TYPE" = "ubuntu" ] ; then
    MOD_SSL_LOCATION="/usr/lib/apache2/modules/mod_ssl.so"
    APACHE_NAME=apache2ctl
elif [ "$OS_TYPE" = "centos" ]; then
    MOD_SSL_LOCATION="/etc/httpd/modules/mod_ssl.so"
    APACHE_NAME=httpd
fi
OPENSSL_VERSION=$(strings "$MOD_SSL_LOCATION" | egrep -o -m1 '^OpenSSL ([0-9]\.[^ ]+) ' | tail -c +9)
APACHE_VERSION=$(sudo $APACHE_NAME -v | egrep -o 'Apache/([0-9]\.[^ ]+)' | tail -c +8)
"venv/bin/python" tests/letstest/scripts/test_openssl_version.py "$OPENSSL_VERSION" "$APACHE_VERSION"
if [ $? -ne 0 ] ; then
    FAIL=1
fi


if [ "$OS_TYPE" = "ubuntu" ] ; then
    export SERVER="${PEBBLE_URL}"
    "venv/bin/tox" -e apacheconftest
else
    echo Not running hackish apache tests on $OS_TYPE
fi

if [ $? -ne 0 ] ; then
    FAIL=1
fi

# return error if any of the subtests failed
if [ "$FAIL" = 1 ] ; then
    DumpPebbleLogs
    exit 1
fi
