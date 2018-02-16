FROM certbot/certbot:rolling

COPY . src/certbot-dns-cloudflare

RUN pip install --no-cache-dir --editable /opt/certbot/src/certbot-dns-cloudflare
