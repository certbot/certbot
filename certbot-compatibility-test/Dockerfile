FROM debian:jessie
MAINTAINER Brad Warren <bmw@eff.org>

# no need to mkdir anything:
# https://docs.docker.com/reference/builder/#copy
# If <dest> doesn't exist, it is created along with all missing
# directories in its path.

# TODO: Install non-default Python versions for tox.
# TODO: Install Apache/Nginx for plugin development.
COPY letsencrypt-auto-source /opt/certbot/src/letsencrypt-auto-source
RUN /opt/certbot/src/letsencrypt-auto-source/letsencrypt-auto --os-packages-only

# the above is not likely to change, so by putting it further up the
# Dockerfile we make sure we cache as much as possible

COPY setup.py README.rst CHANGELOG.md MANIFEST.in linter_plugin.py tox.cover.py tox.ini .pylintrc /opt/certbot/src/

# all above files are necessary for setup.py, however, package source
# code directory has to be copied separately to a subdirectory...
# https://docs.docker.com/reference/builder/#copy: "If <src> is a
# directory, the entire contents of the directory are copied,
# including filesystem metadata. Note: The directory itself is not
# copied, just its contents." Order again matters, three files are far
# more likely to be cached than the whole project directory

COPY certbot /opt/certbot/src/certbot/
COPY acme /opt/certbot/src/acme/
COPY certbot-apache /opt/certbot/src/certbot-apache/
COPY certbot-nginx /opt/certbot/src/certbot-nginx/
COPY certbot-compatibility-test /opt/certbot/src/certbot-compatibility-test/
COPY tools /opt/certbot/src/tools

RUN VIRTUALENV_NO_DOWNLOAD=1 virtualenv --no-site-packages -p python2 /opt/certbot/venv && \
    /opt/certbot/venv/bin/pip install -U setuptools && \
    /opt/certbot/venv/bin/pip install -U pip
ENV PATH /opt/certbot/venv/bin:$PATH
RUN /opt/certbot/venv/bin/python \
    /opt/certbot/src/tools/pip_install_editable.py \
    /opt/certbot/src/acme \
    /opt/certbot/src \
    /opt/certbot/src/certbot-apache \
    /opt/certbot/src/certbot-nginx \
    /opt/certbot/src/certbot-compatibility-test

# install in editable mode (-e) to save space: it's not possible to
# "rm -rf /opt/certbot/src" (it's stays in the underlaying image);
# this might also help in debugging: you can "docker run --entrypoint
# bash" and investigate, apply patches, etc.

WORKDIR /opt/certbot/src/certbot-compatibility-test/certbot_compatibility_test/testdata
