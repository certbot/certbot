FROM certbot/certbot

COPY . src/certbot-dns-gehirn

RUN pip install --constraint docker_constraints.txt --no-cache-dir --editable src/certbot-dns-gehirn
