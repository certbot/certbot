#base image
FROM python:3.12-alpine3.18 AS certbot

ENTRYPOINT [ "certbot" ]
EXPOSE 80 443
VOLUME /etc/letsencrypt /var/lib/letsencrypt
WORKDIR /opt/certbot

# Copy certbot code
COPY CHANGELOG.md README.rst src/
COPY tools tools
COPY acme src/acme
COPY certbot src/certbot

# Install certbot runtime dependencies
RUN apk add --no-cache --virtual .certbot-deps \
        libffi \
        libssl1.1 \
        openssl \
        ca-certificates \
        binutils

# We set this environment variable and install git while building to try and
# increase the stability of fetching the rust crates needed to build the
# cryptography library
ARG CARGO_NET_GIT_FETCH_WITH_CLI=true
# Install certbot from sources
RUN apk add --no-cache --virtual .build-deps \
        gcc \
        linux-headers \
        openssl-dev \
        musl-dev \
        libffi-dev \
        python3-dev \
        cargo \
        git \
        pkgconfig \
    && python tools/pip_install.py --no-cache-dir \
            --editable src/acme \
            --editable src/certbot \
    && apk del .build-deps \
    && rm -rf ${HOME}/.cargo

#static definition for making a plugin, but beware that
#using this layer definition will cause collisions if you make
#extensive use of the cache.
FROM certbot AS certbot-plugin
COPY --from=plugin-src . /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin
