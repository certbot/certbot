FROM certbot/certbot

COPY . src/certbot-dns-nsone

RUN pip install -r src/certbot-dns-nsone/plugin_dependencies.txt \
    && pip install --no-cache-dir --editable src/certbot-dns-nsone
