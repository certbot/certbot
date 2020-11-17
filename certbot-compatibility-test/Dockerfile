FROM debian:buster
MAINTAINER Brad Warren <bmw@eff.org>

RUN apt-get update && \
    apt install python3-dev python3-venv gcc libaugeas0 libssl-dev \
                 libffi-dev ca-certificates openssl -y

WORKDIR /opt/certbot/src

# We copy all contents of the build directory to allow us to easily use
# things like tools/venv3.py which expects all of our packages to be available.
COPY . .

RUN tools/venv3.py
ENV PATH /opt/certbot/src/venv3/bin:$PATH

# install in editable mode (-e) to save space: it's not possible to
# "rm -rf /opt/certbot/src" (it's stays in the underlaying image);
# this might also help in debugging: you can "docker run --entrypoint
# bash" and investigate, apply patches, etc.

WORKDIR /opt/certbot/src/certbot-compatibility-test/certbot_compatibility_test/testdata
