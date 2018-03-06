#!/bin/sh
curl -X POST 'http://localhost:8055/clear-txt' -d \
    "{\"host\": \"_acme-challenge.$CERTBOT_DOMAIN.\"}"
