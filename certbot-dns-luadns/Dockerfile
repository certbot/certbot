FROM certbot/certbot

COPY . src/certbot-dns-luadns

RUN pip install -r src/certbot-dns-luadns/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-luadns
