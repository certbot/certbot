FROM certbot/certbot

COPY . src/certbot-dns-gehirn

RUN pip install -r src/certbot-dns-gehirn/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-gehirn
