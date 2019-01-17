FROM certbot/certbot

COPY . src/certbot-dns-google

RUN pip install -r src/certbot-dns-google/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-google
