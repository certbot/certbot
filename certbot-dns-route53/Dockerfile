FROM certbot/certbot

COPY . src/certbot-dns-route53

RUN pip install --constraint docker_constraints.txt --no-cache-dir --editable src/certbot-dns-route53
