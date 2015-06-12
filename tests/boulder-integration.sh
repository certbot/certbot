#!/bin/sh
# Simple integration test, run as "./boulder-integration.sh auth" or
# adjust parameters: "./boulder-integration.sh --domain bang auth".

root="$(mktemp -d)"

# first three flags required, rest is handy defaults
letsencrypt \
  --server http://localhost:4000/acme/new-reg \
  --no-verify-ssl \
  --dvsni-port 5001 \
  --config-dir "$root/conf" \
  --work-dir "$root/work" \
  --text \
  --agree-tos \
  --email "" \
  --domains le.wtf \
  -vvvvvvv \
  "$@"

# print at the end, so it's more visible
echo "\nRoot integration tests directory: $root"
