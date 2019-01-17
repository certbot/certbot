FROM certbot/certbot

COPY . src/certbot-dns-dnsimple

RUN pip install -r src/certbot-dns-dnsimple/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-dnsimple
