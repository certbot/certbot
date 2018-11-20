#!/bin/bash

set -e

if [ "$INTEGRATION_TEST" = "certbot" ]; then
    tests/certbot-boulder-integration.sh
elif [ "$INTEGRATION_TEST" = "nginx" ]; then
    certbot-nginx/tests/boulder-integration.sh
else
   tests/certbot-boulder-integration.sh
    # Most CI systems set this variable to true.
    # If the tests are running as part of CI, Nginx should be available.
    if ${CI:-false} || type nginx; then
        certbot-nginx/tests/boulder-integration.sh
    fi
fi
