#!/bin/bash

# If domain begins with fail, we didn't complete the challenge so there is
# nothing to clean up.
if [[ "$CERTBOT_DOMAIN" != fail* ]]; then
    curl -X POST "http://boulder:8055/clear-txt" -d \
        "{\"host\": \"_acme-challenge.$CERTBOT_DOMAIN.\"}"
fi
