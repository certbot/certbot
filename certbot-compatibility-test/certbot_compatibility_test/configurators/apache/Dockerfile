FROM httpd
MAINTAINER Brad Warren <bradmw@umich.edu>

RUN mkdir /var/run/apache2

ENV APACHE_RUN_USER=daemon \
    APACHE_RUN_GROUP=daemon \
    APACHE_PID_FILE=/usr/local/apache2/logs/httpd.pid \
    APACHE_RUN_DIR=/var/run/apache2 \
    APACHE_LOCK_DIR=/var/lock \
    APACHE_LOG_DIR=/usr/local/apache2/logs 

COPY certbot-compatibility-test/certbot_compatibility_test/configurators/apache/a2enmod.sh /usr/local/bin/
COPY certbot-compatibility-test/certbot_compatibility_test/configurators/apache/a2dismod.sh /usr/local/bin/
COPY certbot-compatibility-test/certbot_compatibility_test/testdata/rsa1024_key2.pem /usr/local/apache2/conf/
COPY certbot-compatibility-test/certbot_compatibility_test/testdata/empty_cert.pem /usr/local/apache2/conf/

# Note: this only exposes the port to other docker containers. You
# still have to bind to 443@host at runtime.
EXPOSE 443
