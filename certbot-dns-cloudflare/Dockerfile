FROM certbot/certbot

COPY . src/certbot-dns-cloudflare

RUN pip install -c docker_constraints.txt --no-cache-dir --editable src/certbot-dns-cloudflare
