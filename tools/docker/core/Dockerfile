# Docker Arch (amd64, arm32v6, ...)
ARG TARGET_ARCH
FROM ${TARGET_ARCH}/python:3.8-alpine3.12

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
# We keep the relative path to the requirements file the same because, as of
# writing this, tools/pip_install.py is used in the Dockerfile for Certbot
# plugins and this script expects to find the requirements file there.
COPY letsencrypt-auto-source/pieces/dependency-requirements.txt letsencrypt-auto-source/pieces/
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

# Install certbot from sources
#
# We don't use tools/pip_install.py below so the hashes in
# dependency-requirements.txt can be used when installing packages for extra
# security.
RUN apk add --no-cache --virtual .build-deps \
        gcc \
        linux-headers \
        openssl-dev \
        musl-dev \
        libffi-dev \
    && python tools/pipstrap.py \
    && python tools/pip_install.py --no-cache-dir \
            --editable src/acme \
            --editable src/certbot \
    && apk del .build-deps
