ARG CACHE_TAG=latest
FROM certbot/certbot:${CACHE_TAG}

COPY . src/certbot-dns-cloudflare

RUN pip install --no-cache-dir --editable /opt/certbot/src/certbot-dns-cloudflare
