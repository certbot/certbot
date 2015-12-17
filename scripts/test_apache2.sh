#!/bin/bash -x

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL
# are dynamically set at execution

if [ "$OS_TYPE" = "ubuntu" ]
then
    CONFFILE=/etc/apache2/sites-available/000-default.conf
    sudo apt-get update
    sudo apt-get -y --no-upgrade install apache2 #curl
    # For apache 2.4, set up ServerName
    sudo sed -i '/ServerName/ s/#ServerName/ServerName/' $CONFFILE
    sudo sed -i '/ServerName/ s/www.example.com/'$PUBLIC_HOSTNAME'/' $CONFFILE
elif [ "$OS_TYPE" = "centos" ]
then
    CONFFILE=/etc/httpd/conf/httpd.conf
    sudo setenforce 0 || true #disable selinux
    sudo yum -y install httpd
    sudo service httpd start
    sudo mkdir -p /var/www/$PUBLIC_HOSTNAME/public_html
    sudo chmod -R oug+rwx /var/www
    sudo chmod -R oug+rw /etc/httpd
    sudo echo '<html><head><title>foo</title></head><body>bar</body></html>' > /var/www/$PUBLIC_HOSTNAME/public_html/index.html
    sudo mkdir /etc/httpd/sites-available #letsencrypt requires this...
    sudo mkdir /etc/httpd/sites-enabled #letsencrypt requires this...
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

# run letsencrypt-apache2 via letsencrypt-auto
cd letsencrypt
./letsencrypt-auto -v --debug --text --agree-dev-preview --agree-tos \
                   --renew-by-default --redirect --register-unsafely-without-email \
                   --domain $PUBLIC_HOSTNAME --server $BOULDER_URL
if [ $? -ne 0 ] ; then
    FAIL=1
fi

if [ "$OS_TYPE" = "ubuntu" ] ; then
    export LETSENCRYPT="$HOME/.local/share/letsencrypt/bin/letsencrypt"
    for mod in `grep -v '^#' tests/apache-conf-files/passing/README.modules` ; do
        sudo a2enmod $mod
    done
    tests/apache-conf-files/hackish-apache-test
else
    echo Not running hackish apache tests on $OS_TYPE
fi

if [ $? -ne 0 ] ; then
    FAIL=1
fi

# return error if any of the subtests failed
if [ "$FAIL" = 1 ] ; then
    return 1
fi
