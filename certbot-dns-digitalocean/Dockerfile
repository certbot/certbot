FROM certbot/certbot

COPY . src/certbot-dns-digitalocean

RUN pip install -r src/certbot-dns-digitalocean/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-digitalocean
