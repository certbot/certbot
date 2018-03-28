FROM certbot/certbot:latest
MAINTAINER Sydney Li

WORKDIR /opt/certbot-postfix

RUN apk add --no-cache --update postfix \
        ca-certificates \
        supervisor \
        rsyslog \
        bash

# Postfix isn't very docker-friendly-- also need to DL rsyslog and
# run them via supervisord.
COPY docker-files/supervisord.conf /etc/supervisord.conf
COPY docker-files/rsyslog.conf /etc/rsyslog.conf
COPY certbot_postfix/ certbot_postfix/
COPY setup.py setup.py

RUN pip install --no-cache-dir --editable .

ADD tests tests
ADD testdata testdata

RUN mkdir /var/mail
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
EXPOSE 25
