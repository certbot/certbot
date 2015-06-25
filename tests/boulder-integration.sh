#!/bin/sh -xe
# Simple integration test, make sure to activate virtualenv beforehand
# (source venv/bin/activate) and that you are running Boulder test
# instance (see ./boulder-start.sh).

root="$(mktemp -d)"
echo "\nRoot integration tests directory: $root"

common() {
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
        --authenticator standalone \
        -vvvvvvv "$@"
}

common --domains le.wtf auth

export CSR_PATH="${root}/csr.der" OPENSSL_CNF=examples/openssl.cnf
./examples/generate-csr.sh le.wtf
common auth --csr "$CSR_PATH" \
       --cert-path "${root}/csr/cert.pem" \
       --chain-path "${root}/csr/chain.pem"
openssl x509 -in "${root}/csr/0000_cert.pem" -text
openssl x509 -in "${root}/csr/0000_chain.pem" -text
