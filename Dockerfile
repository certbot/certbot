FROM python:2-alpine3.9

ENTRYPOINT [ "certbot" ]
EXPOSE 80 443
VOLUME /etc/letsencrypt /var/lib/letsencrypt
WORKDIR /opt/certbot

COPY CHANGELOG.md README.rst setup.py src/

# Generate constraints file to pin dependency versions
COPY letsencrypt-auto-source/pieces/dependency-requirements.txt .
COPY tools /opt/certbot/tools
RUN sh -c 'cat dependency-requirements.txt | /opt/certbot/tools/strip_hashes.py > unhashed_requirements.txt'
RUN sh -c 'cat tools/dev_constraints.txt unhashed_requirements.txt | /opt/certbot/tools/merge_requirements.py > docker_constraints.txt'

COPY acme src/acme
COPY certbot src/certbot

RUN apk add --no-cache --virtual .certbot-deps \
        libffi \
        libssl1.1 \
        openssl \
        ca-certificates \
        binutils
RUN apk add --no-cache --virtual .build-deps \
        gcc \
        linux-headers \
        openssl-dev \
        musl-dev \
        libffi-dev \
    && pip install -r /opt/certbot/dependency-requirements.txt \
    && pip install --no-cache-dir --no-deps \
        --editable /opt/certbot/src/acme \
        --editable /opt/certbot/src \
    && apk del .build-deps
