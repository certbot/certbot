FROM certbot/certbot

COPY . src/certbot-dns-ovh

RUN pip install -r src/certbot-dns-ovh/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-ovh
