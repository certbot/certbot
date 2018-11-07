#!/bin/bash

# If domain begins with fail, fail the challenge by not completing it.
if [[ "$CERTBOT_DOMAIN" != fail* ]]; then
    curl -X POST 'http://localhost:8055/set-txt' -d \
        "{\"host\": \"_acme-challenge.$CERTBOT_DOMAIN.\", \
         \"value\": \"$CERTBOT_VALIDATION\"}"
fi
