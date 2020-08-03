#!/bin/bash -x

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL
# are dynamically set at execution

if [ "$OS_TYPE" = "ubuntu" ]
then
    CONFFILE=/etc/apache2/sites-available/000-default.conf
    sudo apt-get update
    sudo apt-get -y --no-upgrade install apache2 #curl
    sudo apt-get -y install realpath # needed for test-apache-conf
    # For apache 2.4, set up ServerName
    sudo sed -i '/ServerName/ s/#ServerName/ServerName/' $CONFFILE
    sudo sed -i '/ServerName/ s/www.example.com/'$PUBLIC_HOSTNAME'/' $CONFFILE
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
letsencrypt-auto-source/letsencrypt-auto --os-packages-only
if [ $? -ne 0 ] ; then
    exit 1
fi

# This script sets the environment variables PYTHON_NAME, VENV_PATH, and
# VENV_SCRIPT based on the version of Python available on the system. For
# instance, Fedora uses Python 3 and Python 2 is not installed.
. tests/letstest/scripts/set_python_envvars.sh

"$VENV_SCRIPT" -e acme[dev] -e certbot[dev,docs] -e certbot-apache
sudo "$VENV_PATH/bin/certbot" -v --debug --text --agree-tos \
                   --renew-by-default --redirect --register-unsafely-without-email \
                   --domain $PUBLIC_HOSTNAME --server $BOULDER_URL
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
"$PYTHON_NAME" tests/letstest/scripts/test_openssl_version.py "$OPENSSL_VERSION" "$APACHE_VERSION"
if [ $? -ne 0 ] ; then
    FAIL=1
fi


if [ "$OS_TYPE" = "ubuntu" ] ; then
    export SERVER="$BOULDER_URL"
    "$VENV_PATH/bin/tox" -e apacheconftest
else
    echo Not running hackish apache tests on $OS_TYPE
fi

if [ $? -ne 0 ] ; then
    FAIL=1
fi

# return error if any of the subtests failed
if [ "$FAIL" = 1 ] ; then
    exit 1
fi
