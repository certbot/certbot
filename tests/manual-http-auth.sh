#!/bin/sh
cd $(mktemp -d)
mkdir -p .well-known/acme-challenge
echo $CERTBOT_VALIDATION > ".well-known/acme-challenge/$CERTBOT_TOKEN"
python -m SimpleHTTPServer $http_01_port >/dev/null 2>&1 &
echo $!
