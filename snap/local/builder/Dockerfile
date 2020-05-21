ARG TARGET_ARCH
FROM ${TARGET_ARCH}/ubuntu:bionic as builder

ARG QEMU_ARCH
COPY qemu-${QEMU_ARCH}-static /usr/bin/

# Grab dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq squashfs-tools \
 && rm -rf /var/lib/apt/lists/*

ARG SNAP_ARCH

# Grab the core snap from the stable channel and unpack it in the proper place
RUN curl -L $(curl -H 'X-Ubuntu-Series: 16' -H "X-Ubuntu-Architecture: $SNAP_ARCH" 'https://api.snapcraft.io/api/v1/snaps/details/core' | jq '.download_url' -r) --output core.snap \
 && mkdir -p /snap/core \
 && unsquashfs -d /snap/core/current core.snap

# Grab the core18 snap from the stable channel and unpack it in the proper place
RUN curl -L $(curl -H 'X-Ubuntu-Series: 16' -H "X-Ubuntu-Architecture: $SNAP_ARCH" 'https://api.snapcraft.io/api/v1/snaps/details/core18' | jq '.download_url' -r) --output core18.snap \
 && mkdir -p /snap/core18 \
 && unsquashfs -d /snap/core18/current core18.snap

# Grab the snapcraft snap from the stable candidate and unpack it in the proper place
# TODO: move back to stable channel once snapcraft 3.10 has been pushed to it.
RUN curl -L $(curl -H 'X-Ubuntu-Series: 16' -H "X-Ubuntu-Architecture: $SNAP_ARCH" 'https://api.snapcraft.io/api/v1/snaps/details/snapcraft?channel=candidate' | jq '.download_url' -r) --output snapcraft.snap \
 && mkdir -p /snap/snapcraft \
 && unsquashfs -d /snap/snapcraft/current snapcraft.snap

# Create a snapcraft runner (TODO: move version detection to the core of snapcraft)
RUN mkdir -p /snap/bin \
 && echo "#!/bin/sh" > /snap/bin/snapcraft \
 && snap_version="$(awk '/^version:/{print $2}' /snap/snapcraft/current/meta/snap.yaml)" && echo "export SNAP_VERSION=\"$snap_version\"" >> /snap/bin/snapcraft \
 && echo 'exec "$SNAP/usr/bin/python3" "$SNAP/bin/snapcraft" "$@"' >> /snap/bin/snapcraft \
 && chmod +x /snap/bin/snapcraft

# Multi-stage build, only need the snaps from the builder. Copy them one at a time so they can be cached.
FROM ${TARGET_ARCH}/ubuntu:bionic

ARG QEMU_ARCH
COPY qemu-${QEMU_ARCH}-static /usr/bin/

COPY --from=builder /snap/core /snap/core
COPY --from=builder /snap/core18 /snap/core18
COPY --from=builder /snap/snapcraft /snap/snapcraft
COPY --from=builder /snap/bin/snapcraft /snap/bin/snapcraft

# Generate locale and add runtime dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo locales git \
 && locale-gen en_US.UTF-8 \
 && rm -rf /var/lib/apt/lists/*

# Set the proper environment
ENV LANG="en_US.UTF-8"
ENV LANGUAGE="en_US:en"
ENV LC_ALL="en_US.UTF-8"
ENV PATH="/snap/bin:$PATH"
ENV SNAP="/snap/snapcraft/current"
ENV SNAP_NAME="snapcraft"

ARG SNAP_ARCH
ENV SNAP_ARCH="${SNAP_ARCH}"
