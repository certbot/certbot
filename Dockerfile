FROM ubuntu:trusty

EXPOSE 443

RUN apt-get update && apt-get -y install python python-setuptools python-virtualenv python-dev \
  gcc swig dialog libaugeas0 libssl-dev libffi-dev ca-certificates git && \
  apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN cd /opt && git clone https://github.com/letsencrypt/lets-encrypt-preview.git
WORKDIR /opt/lets-encrypt-preview
RUN \
  virtualenv --no-site-packages -p python2 venv && \
  ./venv/bin/python setup.py install

ENTRYPOINT [ "./venv/bin/letsencrypt", "--text" ]
