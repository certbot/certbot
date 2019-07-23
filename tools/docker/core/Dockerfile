FROM python:2-alpine3.10

ARG CERTBOT_VERSION
ENV CERTBOT_VERSION=${CERTBOT_VERSION}

ENTRYPOINT [ "certbot" ]
EXPOSE 80 443
VOLUME /etc/letsencrypt /var/lib/letsencrypt
WORKDIR /opt/certbot

# Retrieve certbot code
RUN mkdir -p src \
 && wget -O certbot-${CERTBOT_VERSION}.tar.gz https://github.com/certbot/certbot/archive/v${CERTBOT_VERSION}.tar.gz \
 && tar xf certbot-${CERTBOT_VERSION}.tar.gz \
 && cp certbot-${CERTBOT_VERSION}/CHANGELOG.md certbot-${CERTBOT_VERSION}/README.rst certbot-${CERTBOT_VERSION}/setup.py src/ \
 && cp certbot-${CERTBOT_VERSION}/letsencrypt-auto-source/pieces/dependency-requirements.txt . \
 && cp -r certbot-${CERTBOT_VERSION}/tools tools \
 && cp -r certbot-${CERTBOT_VERSION}/acme src/acme \
 && cp -r certbot-${CERTBOT_VERSION}/certbot src/certbot \
 && rm -rf certbot-${CERTBOT_VERSION}.tar.gz certbot-${CERTBOT_VERSION}

# Generate constraints file to pin dependency versions
RUN cat dependency-requirements.txt | tools/strip_hashes.py > unhashed_requirements.txt \
 && cat tools/dev_constraints.txt unhashed_requirements.txt | tools/merge_requirements.py > docker_constraints.txt

# Install certbot runtime dependencies
RUN apk add --no-cache --virtual .certbot-deps \
        libffi \
        libssl1.1 \
        openssl \
        ca-certificates \
        binutils

# Install certbot from sources
RUN apk add --no-cache --virtual .build-deps \
        gcc \
        linux-headers \
        openssl-dev \
        musl-dev \
        libffi-dev \
    && pip install -r dependency-requirements.txt \
    && pip install --no-cache-dir --no-deps \
        --editable src/acme \
        --editable src \
&& apk del .build-deps
