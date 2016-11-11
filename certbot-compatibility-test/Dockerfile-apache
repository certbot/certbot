FROM certbot-compatibility-test
MAINTAINER Brad Warren <bmw@eff.org>

RUN apt-get install apache2 -y

ENTRYPOINT [ "certbot-compatibility-test", "-p", "apache" ]
