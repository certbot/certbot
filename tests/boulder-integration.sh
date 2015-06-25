#!/bin/sh -xe
# Simple integration test, make sure to activate virtualenv beforehand
# (source venv/bin/activate) and that you are running Boulder test
# instance (see ./boulder-start.sh).

root="$(mktemp -d)"
echo "\nRoot integration tests directory: $root"

# first three flags required, rest is handy defaults
letsencrypt \
  --server http://localhost:4000/acme/new-reg \
  --no-verify-ssl \
  --dvsni-port 5001 \
  --config-dir "$root/conf" \
  --work-dir "$root/work" \
  --text \
  --agree-eula \
  --email "" \
  --domains le.wtf \
  --authenticator standalone \
  -vvvvvvv \
  auth
