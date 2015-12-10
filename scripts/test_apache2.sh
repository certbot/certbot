#!/bin/bash -x

#install apache2 on apt systems
# debian doesn't come with curl
#sudo apt-get update
#sudo apt-get -y --no-upgrade install apache2 #curl

# $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME $BOULDER_URL are dynamically set at execution
# fetch instance data from EC2 metadata service
#public_host=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-hostname)
#public_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/public-ipv4)
#private_ip=$(curl -s http://169.254.169.254/2014-11-05/meta-data/local-ipv4)

if [ $OS_TYPE = "ubuntu" ]
then
    CONFFILE=/etc/apache2/sites-available/000-default.conf
    sudo apt-get update
    sudo apt-get -y --no-upgrade install apache2 #curl
    # For apache 2.4, set up ServerName
    sudo sed -i '/ServerName/ s/#ServerName/ServerName/' $CONFFILE
    sudo sed -i '/ServerName/ s/www.example.com/'$PUBLIC_HOSTNAME'/' $CONFFILE
elif [ $OS_TYPE = "centos" ]
then
    CONFFILE=/etc/httpd/conf/httpd.conf
    sudo yum -y install httpd
    sudo service httpd start
    sudo mkdir -p /var/www/$PUBLIC_HOSTNAME/public_html
    sudo chmod -R 777 /var/www
    sudo echo '<html><head><title>foo</title></head>\n<body>bar</body></html>' > /var/www/$PUBLIC_HOSTNAME/public_html/index.html
    sudo mkdir /etc/httpd/sites-available
    sudo mkdir /etc/httpd/sites-enabled
    sudo echo "IncludeOptional sites-enabled/*.conf" >> /etc/httpd/conf/httpd.conf
    sudo echo """
<VirtualHost *:80>
    ServerName $PUBLIC_HOSTNAME
    DocumentRoot /var/www/$PUBLIC_HOSTNAME/public_html
    ErrorLog /var/www/$PUBLIC_HOSTNAME/error.log
    CustomLog /var/www/$PUBLIC_HOSTNAME/requests.log combined
</VirtualHost>""" >> /etc/httpd/sites-available/$PUBLIC_HOSTNAME.conf
    sudo cp /etc/httpd/sites-available/$PUBLIC_HOSTNAME.conf /etc/httpd/sites-enabled/
fi

# run letsencrypt-apache2 via letsencrypt-auto
cd letsencrypt
./bootstrap/install-deps.sh
./bootstrap/dev/venv.sh
source ./venv/bin/activate
sudo ./venv/bin/letsencrypt -v --debug --text --agree-dev-preview --agree-tos \
                   --renew-by-default --redirect --register-unsafely-without-email \
                   --domain $PUBLIC_HOSTNAME --server $BOULDER_URL
