# Docker Arch (amd64, arm32v6, ...)
ARG TARGET_ARCH
ARG TAG_BASE
FROM certbot/certbot:${TARGET_ARCH}-${TAG_BASE}

# Qemu Arch (x86_64, arm, ...)
ARG QEMU_ARCH
ENV QEMU_ARCH=${QEMU_ARCH}
COPY qemu-${QEMU_ARCH}-static /usr/bin/

# Copy Certbot DNS plugin code
COPY . /opt/certbot/src/plugin

# Install the DNS plugin
RUN pip install --constraint /opt/certbot/docker_constraints.txt --no-cache-dir --editable /opt/certbot/src/plugin
