# For running tests, build a docker image with a passwordless sudo and a trust
# store we can manipulate.

FROM centos:6

RUN yum install -y epel-release

# Install pip and sudo:
RUN yum install -y python-pip sudo
# Update to a stable and tested version of pip.
# We do not use pipstrap here because it no longer supports Python 2.6.
RUN pip install pip==9.0.1 setuptools==29.0.1 wheel==0.29.0
# Pin pytest version for increased stability
RUN pip install pytest==3.2.5 six==1.10.0

# Add an unprivileged user:
RUN useradd --create-home --home-dir /home/lea --shell /bin/bash --groups wheel --uid 1000 lea

# Let that user sudo:
RUN sed -i.bkp -e \
      's/# %wheel\(NOPASSWD: ALL\)\?/%wheel/g' \
      /etc/sudoers

RUN mkdir -p /home/lea/certbot

# Install fake testing CA:
COPY ./tests/certs/ca/my-root-ca.crt.pem /usr/local/share/ca-certificates/
RUN update-ca-trust

# Copy code:
COPY . /home/lea/certbot/letsencrypt-auto-source

USER lea
WORKDIR /home/lea

RUN sudo chmod +x certbot/letsencrypt-auto-source/tests/centos6_tests.sh
CMD sudo certbot/letsencrypt-auto-source/tests/centos6_tests.sh
