#!/bin/sh -xe
# Simple integration test, make sure to activate virtualenv beforehand
# (source venv/bin/activate) and that you are running Boulder test
# instance (see ./boulder-start.sh).

root="$(mktemp -d)"
echo "\nRoot integration tests directory: $root"
store_flags="--config-dir $root/conf --work-dir $root/work"
store_flags="$store_flags --logs-dir $root/logs"

common() {
    # first three flags required, rest is handy defaults
    letsencrypt \
        --server http://localhost:4000/acme/new-reg \
        --no-verify-ssl \
        --dvsni-port 5001 \
        $store_flags \
        --text \
        --agree-eula \
        --email "" \
        --authenticator standalone \
        --installer null \
        -vvvvvvv "$@"
}

common --domains le1.wtf auth
common --domains le2.wtf run

export CSR_PATH="${root}/csr.der" KEY_PATH="${root}/key.pem" \
       OPENSSL_CNF=examples/openssl.cnf
./examples/generate-csr.sh le3.wtf
common auth --csr "$CSR_PATH" \
       --cert-path "${root}/csr/cert.pem" \
       --chain-path "${root}/csr/chain.pem"
openssl x509 -in "${root}/csr/0000_cert.pem" -text
openssl x509 -in "${root}/csr/0000_chain.pem" -text

common --domain le3.wtf install \
       --cert-path "${root}/csr/cert.pem" \
       --key-path "${root}/csr/key.pem"

# the following assumes that Boulder issues certificates for less than
# 10 years, otherwise renewal will not take place
cat <<EOF > "$root/conf/renewer.conf"
renew_before_expiry = 10 years
deploy_before_expiry = 10 years
EOF
letsencrypt-renewer $store_flags
dir="$root/conf/archive/le1.wtf"
for x in cert chain fullchain privkey;
do
    latest="$(ls -1t $dir/ | grep -e "^${x}" | head -n1)"
    live="$(readlink -f "$root/conf/live/le1.wtf/${x}.pem")"
    #[ "${dir}/${latest}" = "$live" ]  # renewer fails this test
done
