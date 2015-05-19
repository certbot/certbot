FROM ubuntu:trusty

EXPOSE 443

ENV DEBIAN_FRONTEND noninteractive

WORKDIR /opt
ADD bootstrap/ubuntu.sh ./bootstrap/ubuntu.sh

# Install and clean in one step to avoid large docker history.
# Install without virtualenv, since this is in a containerized
# environment anyway.
RUN \
  bootstrap/ubuntu.sh no_venv && \
  apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Gather all the requirements to run setup.py
ADD setup.py README.rst CHANGES.rst MANIFEST.in ./
ADD letsencrypt ./letsencrypt/
ADD acme ./acme/
ADD letsencrypt_apache ./letsencrypt_apache/
ADD letsencrypt_nginx ./letsencrypt_nginx/

RUN python setup.py install

VOLUME /etc/letsencrypt /var/lib/letsencrypt
CMD [ "/bin/bash" ]
