FROM certbot/certbot

COPY . src/certbot-dns-cloudflare

RUN pip install -r src/certbot-dns-cloudflare/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-cloudflare
