FROM certbot/certbot

COPY . src/certbot-dns-route53

RUN pip install -r src/certbot-dns-route53/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-route53
