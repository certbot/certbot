#base image 
FROM python:3.10-alpine3.16 as certbot

ENTRYPOINT [ "certbot" ]
EXPOSE 80 443
VOLUME /etc/letsencrypt /var/lib/letsencrypt
WORKDIR /opt/certbot

# Copy certbot code
COPY CHANGELOG.md README.rst src/
COPY tools tools
COPY acme src/acme
COPY certbot src/certbot

# Install certbot runtime dependencies
RUN apk add --no-cache --virtual .certbot-deps \
        libffi \
        libssl1.1 \
        openssl \
        ca-certificates \
        binutils

# We set this environment variable and install git while building to try and
# increase the stability of fetching the rust crates needed to build the
# cryptography library
ARG CARGO_NET_GIT_FETCH_WITH_CLI=true
# Install certbot from sources
RUN apk add --no-cache --virtual .build-deps \
        gcc \
        linux-headers \
        openssl-dev \
        musl-dev \
        libffi-dev \
        python3-dev \
        cargo \
        git \
    && python tools/pipstrap.py \
    && python tools/pip_install.py --no-cache-dir \
            --editable src/acme \
            --editable src/certbot \
    && apk del .build-deps \
    && rm -rf ${HOME}/.cargo

#static definition for making a plugin, but beware that
#using this layer definition will cause collisions if you make
#extensive use of the cache.
FROM certbot as certbot-plugin
COPY --from=plugin-src . /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-dnsmadeeasy
COPY certbot-dns-dnsmadeeasy /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-dnsimple
COPY certbot-dns-dnsimple /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-ovh
COPY certbot-dns-ovh /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-cloudflare
COPY certbot-dns-cloudflare /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-digitalocean
COPY certbot-dns-digitalocean /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-google
COPY certbot-dns-google /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-luadns
COPY certbot-dns-luadns /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-nsone
COPY certbot-dns-nsone /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-rfc2136
COPY certbot-dns-rfc2136 /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-route53
COPY certbot-dns-route53 /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-gehirn
COPY certbot-dns-gehirn /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-linode
COPY certbot-dns-linode /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

FROM certbot as certbot-dns-sakuracloud
COPY certbot-dns-sakuracloud /opt/certbot/src/plugin
RUN python tools/pip_install.py --no-cache-dir --editable /opt/certbot/src/plugin

