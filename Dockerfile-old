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
VOLUME /etc/letsencrypt /var/lib/letsencrypt

WORKDIR /opt/certbot

# no need to mkdir anything:
# https://docs.docker.com/reference/builder/#copy
# If <dest> doesn't exist, it is created along with all missing
# directories in its path.

ENV DEBIAN_FRONTEND=noninteractive

COPY letsencrypt-auto-source/letsencrypt-auto /opt/certbot/src/letsencrypt-auto-source/letsencrypt-auto
RUN /opt/certbot/src/letsencrypt-auto-source/letsencrypt-auto --os-packages-only && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* \
           /tmp/* \
           /var/tmp/*

# the above is not likely to change, so by putting it further up the
# Dockerfile we make sure we cache as much as possible


COPY setup.py README.rst CHANGELOG.md MANIFEST.in letsencrypt-auto-source/pieces/pipstrap.py /opt/certbot/src/

# all above files are necessary for setup.py and venv setup, however,
# package source code directory has to be copied separately to a
# subdirectory...
# https://docs.docker.com/reference/builder/#copy: "If <src> is a
# directory, the entire contents of the directory are copied,
# including filesystem metadata. Note: The directory itself is not
# copied, just its contents." Order again matters, three files are far
# more likely to be cached than the whole project directory

COPY certbot /opt/certbot/src/certbot/
COPY acme /opt/certbot/src/acme/
COPY certbot-apache /opt/certbot/src/certbot-apache/
COPY certbot-nginx /opt/certbot/src/certbot-nginx/


RUN VIRTUALENV_NO_DOWNLOAD=1 virtualenv --no-site-packages -p python2 /opt/certbot/venv

# PATH is set now so pipstrap upgrades the correct (v)env
ENV PATH /opt/certbot/venv/bin:$PATH
RUN /opt/certbot/venv/bin/python /opt/certbot/src/pipstrap.py && \
    /opt/certbot/venv/bin/pip install \
    -e /opt/certbot/src/acme \
    -e /opt/certbot/src \
    -e /opt/certbot/src/certbot-apache \
    -e /opt/certbot/src/certbot-nginx

# install in editable mode (-e) to save space: it's not possible to
# "rm -rf /opt/certbot/src" (it's stays in the underlaying image);
# this might also help in debugging: you can "docker run --entrypoint
# bash" and investigate, apply patches, etc.

# set up certbot/letsencrypt wrapper to warn people about Dockerfile changes
COPY tools/docker-warning.sh /opt/certbot/bin/certbot
RUN ln -s /opt/certbot/bin/certbot /opt/certbot/bin/letsencrypt
ENV PATH /opt/certbot/bin:$PATH

ENTRYPOINT [ "certbot" ]
