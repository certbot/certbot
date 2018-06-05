#!/bin/bash

set -e

if [ "$TOXENV" != "py27-nginx-oldest" ]; then
   tests/certbot-boulder-integration.sh
fi
if [ "$TOXENV" != "py27-certbot-oldest" ]; then
    # Most CI systems set this variable to true.
    # If the tests are running as part of CI, Nginx should be available.
    if ${CI:-false} || type nginx; then
        certbot-nginx/tests/boulder-integration.sh
    fi
fi
