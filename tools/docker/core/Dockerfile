# Docker Arch (amd64, arm32v6, ...)
ARG TARGET_ARCH
FROM ${TARGET_ARCH}/python:3.10-alpine3.16

# Qemu Arch (x86_64, arm, ...)
ARG QEMU_ARCH
ENV QEMU_ARCH=${QEMU_ARCH}
COPY qemu-${QEMU_ARCH}-static /usr/bin/

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
    && python tools/pip_install.py --no-cache-dir \
            --editable src/acme \
            --editable src/certbot \
    && apk del .build-deps \
    && rm -rf ${HOME}/.cargo
