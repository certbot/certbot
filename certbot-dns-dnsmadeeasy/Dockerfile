FROM certbot/certbot

COPY . src/certbot-dns-dnsmadeeasy

RUN pip install -r src/certbot-dns-dnsmadeeasy/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-dnsmadeeasy
