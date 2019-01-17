FROM certbot/certbot

COPY . src/certbot-dns-rfc2136

RUN pip install -r src/certbot-dns-rfc2136/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-rfc2136
