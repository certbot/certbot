FROM certbot/certbot

COPY . src/certbot-dns-cloudxns

RUN pip install -r src/certbot-dns-cloudxns/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-cloudxns
