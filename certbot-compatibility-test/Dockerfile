FROM docker.io/python:3.13-bookworm
LABEL org.opencontainers.image.authors="certbot-dev@eff.org"

# This does not include the dependencies needed to build cryptography. See
# https://cryptography.io/en/latest/installation/#building-cryptography-on-linux
RUN apt-get update && \
    apt install python3-venv libaugeas-dev -y

WORKDIR /opt/certbot/src

# We copy all contents of the build directory to allow us to easily use
# things like tools/venv.py which expects all of our packages to be available.
COPY . .

RUN tools/venv.py
ENV PATH=/opt/certbot/src/venv/bin:$PATH

# install in editable mode (-e) to save space: it's not possible to
# "rm -rf /opt/certbot/src" (it's stays in the underlying image);
# this might also help in debugging: you can "docker run --entrypoint
# bash" and investigate, apply patches, etc.

WORKDIR /opt/certbot/src/certbot-compatibility-test/src/certbot_compatibility_test/testdata
