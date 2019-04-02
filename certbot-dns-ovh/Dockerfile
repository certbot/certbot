FROM certbot/certbot

COPY . src/certbot-dns-ovh

RUN pip install --constraint docker_constraints.txt --no-cache-dir --editable src/certbot-dns-ovh
