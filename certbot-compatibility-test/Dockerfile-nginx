FROM certbot-compatibility-test
MAINTAINER Brad Warren <bmw@eff.org>

RUN apt-get install nginx -y

ENTRYPOINT [ "certbot-compatibility-test", "-p", "nginx" ]
