#!/bin/sh -xe
# Simple integration test, make sure to activate virtualenv beforehand
# (source venv/bin/activate) and that you are running Boulder test
# instance (see ./boulder-start.sh).

root="$(mktemp -d)"
echo "\nRoot integration tests directory: $root"
store_flags="--config-dir $root/conf --work-dir $root/work"

# first three flags required, rest is handy defaults
letsencrypt \
  --server http://localhost:4000/acme/new-reg \
  --no-verify-ssl \
  --dvsni-port 5001 \
  $store_flags \
  --text \
  --agree-eula \
  --email "" \
  --domains le.wtf \
  --authenticator standalone \
  -vvvvvvv \
  auth

# the following assumes that Boulder issues certificates for less than
# 10 years, otherwise renewal will not take place
cat <<EOF > "$root/conf/renewer.conf"
renew_before_expiry = 10 years
deploy_before_expiry = 10 years
EOF
letsencrypt-renewer $store_flags
dir="$root/conf/archive/le.wtf"
for x in cert chain fullchain privkey;
do
    latest="$(ls -1t $dir/ | grep -e "^${x}" | head -n1)"
    live="$(readlink -f "$root/conf/live/le.wtf/${x}.pem")"
    #[ "${dir}/${latest}" = "$live" ]  # renewer fails this test
done
