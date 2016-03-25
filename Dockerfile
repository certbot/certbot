# https://github.com/letsencrypt/letsencrypt/pull/431#issuecomment-103659297
# it is more likely developers will already have ubuntu:trusty rather
# than e.g. debian:jessie and image size differences are negligible
FROM ubuntu:trusty
MAINTAINER Jakub Warmuz <jakub@warmuz.org>
MAINTAINER William Budington <bill@eff.org>

# Note: this only exposes the port to other docker containers. You
# still have to bind to 443@host at runtime, as per the ACME spec.
EXPOSE 443

# TODO: make sure --config-dir and --work-dir cannot be changed
# through the CLI (certbot-docker wrapper that uses standalone
# authenticator and text mode only?)

WORKDIR ~/certbot

# No need to mkdir anything:
# https://docs.docker.com/reference/builder/#copy
# If <dest> doesn't exist, it is created along with all missing
# directories in its path.

ENV DEBIAN_FRONTEND=noninteractive

COPY letsencrypt-auto-source/letsencrypt-auto /root/certbot/src/letsencrypt-auto-source/letsencrypt-auto
RUN ~/certbot/src/letsencrypt-auto-source/letsencrypt-auto --os-packages-only && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* \
           /tmp/* \
           /var/tmp/*

# The above is not likely to change, so by putting it further up the
# Dockerfile we make sure we cache as much as possible

COPY letsencrypt-auto-source/pieces/pipstrap.py /root/certbot/src/

# All above files are necessary for setup.py and venv setup

RUN virtualenv --no-site-packages -p python2 ~/certbot/venv

# PATH is set now so pipstrap upgrades the correct (v)env
ENV PATH /root/certbot/venv/bin:$PATH

RUN ~/certbot/venv/bin/python ~/certbot/src/pipstrap.py && \
	~/certbot/venv/bin/pip install letsencrypt


ENTRYPOINT [ "certbot" ]
