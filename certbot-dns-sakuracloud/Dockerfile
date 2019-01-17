FROM certbot/certbot

COPY . src/certbot-dns-sakuracloud

RUN pip install -r src/certbot-dns-sakuracloud/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-sakuracloud
