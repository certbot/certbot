# For running tests, build a docker image with a passwordless sudo and a trust
# store we can manipulate.

FROM ubuntu:xenial

# Add an unprivileged user:
RUN useradd --create-home --home-dir /home/lea --shell /bin/bash --groups sudo --uid 1000 lea

# Install pip, sudo, and openssl:
RUN apt-get update && \
    apt-get -q -y install python-pip sudo openssl && \
    apt-get clean

# Use pipstrap to update to a stable and tested version of pip
COPY ./pieces/pipstrap.py /opt
RUN /opt/pipstrap.py
# Pin pytest version for increased stability
RUN pip install pytest==3.2.5 six==1.10.0

# Let that user sudo:
RUN sed -i.bkp -e \
      's/%sudo\s\+ALL=(ALL\(:ALL\)\?)\s\+ALL/%sudo ALL=NOPASSWD:ALL/g' \
      /etc/sudoers

RUN mkdir -p /home/lea/certbot

# Install fake testing CA:
COPY ./tests/certs/ca/my-root-ca.crt.pem /usr/local/share/ca-certificates/

# Copy code:
COPY . /home/lea/certbot/letsencrypt-auto-source

USER lea
WORKDIR /home/lea

CMD ["pytest", "-v", "-s", "certbot/letsencrypt-auto-source/tests"]
