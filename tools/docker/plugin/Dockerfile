# Certbot image to build on (e.g. certbot/certbot:amd64-v0.35.0)
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# Qemu Arch (x86_64, arm, ...)
ARG QEMU_ARCH
ENV QEMU_ARCH=${QEMU_ARCH}
COPY qemu-${QEMU_ARCH}-static /usr/bin/

# Copy Certbot DNS plugin code
COPY . /opt/certbot/src/plugin

# Install the DNS plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin
