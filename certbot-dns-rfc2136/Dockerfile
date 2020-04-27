FROM certbot/certbot

COPY . src/certbot-dns-rfc2136

RUN pip install --constraint docker_constraints.txt --no-cache-dir --editable src/certbot-dns-rfc2136
