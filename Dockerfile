FROM python:2-alpine3.7

ENTRYPOINT [ "certbot" ]
EXPOSE 80 443
VOLUME /etc/letsencrypt /var/lib/letsencrypt
WORKDIR /opt/certbot

COPY CHANGELOG.md README.rst setup.py src/

# Generate constraints file to pin dependency versions
COPY letsencrypt-auto-source/pieces/dependency-requirements.txt hashed_requirements.txt
COPY tools /opt/certbot/tools
RUN /opt/certbot/tools/docker_constraints.py \
    hashed_requirements.txt unhashed_requirements.txt \
    tools/dev_constraints.txt docker_constraints.txt

COPY acme src/acme
COPY certbot src/certbot

RUN apk add --no-cache --virtual .certbot-deps \
        libffi \
        libssl1.0 \
        openssl \
        ca-certificates \
        binutils
RUN apk add --no-cache --virtual .build-deps \
        gcc \
        linux-headers \
        openssl-dev \
        musl-dev \
        libffi-dev \
    && pip install --no-cache-dir \
        --requirement /opt/certbot/unhashed_requirements.txt \
        --constraint /opt/certbot/docker_constraints.txt \
        --editable /opt/certbot/src/acme \
        --editable /opt/certbot/src \
    && apk del .build-deps
