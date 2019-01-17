FROM certbot/certbot

COPY . src/certbot-dns-linode

RUN pip install -r src/certbot-dns-linode/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-linode
