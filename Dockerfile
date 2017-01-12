FROM python:2-alpine
MAINTAINER Jakub Warmuz <jakub@warmuz.org>
MAINTAINER William Budington <bill@eff.org>

EXPOSE 80 443
VOLUME /etc/letsencrypt /var/lib/letsencrypt
WORKDIR /opt/certbot
ENTRYPOINT [ "certbot" ]
COPY . src

RUN apk add --no-cache --virtual .certbot-deps \
        dialog \
        augeas-libs \
        libffi \
        libssl1.0 \
        wget \
        ca-certificates \
        binutils
RUN apk add --no-cache --virtual .build-deps \
        gcc \
        linux-headers \
        openssl-dev \
        musl-dev \
        libffi-dev \
    && pip install --no-cache-dir \
        --editable /opt/certbot/src/acme \
        --editable /opt/certbot/src \
        --editable /opt/certbot/src/certbot-apache \
        --editable /opt/certbot/src/certbot-nginx \
    && apk del .build-deps
