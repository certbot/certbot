# This Dockerfile builds an image for development.
FROM ubuntu:xenial

# Note: this only exposes the port to other docker containers.
EXPOSE 80 443

WORKDIR /opt/certbot/src

# TODO: Install Apache/Nginx for plugin development.
COPY . .
RUN apt-get update && \
    apt-get install apache2 git nginx-light -y && \
    letsencrypt-auto-source/letsencrypt-auto --os-packages-only && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* \
           /tmp/* \
           /var/tmp/*

RUN VENV_NAME="../venv" python tools/venv.py

ENV PATH /opt/certbot/venv/bin:$PATH
