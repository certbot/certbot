#!/bin/sh -xe
# Simple integration test. Make sure to activate virtualenv beforehand
# (source venv/bin/activate) and that you are running Boulder test
# instance (see ./boulder-start.sh).
#
# Environment variables:
#   SERVER: Passed as "certbot --server" argument.
#
# Note: this script is called by Boulder integration test suite!

. ./tests/integration/_common.sh
export PATH="/usr/sbin:$PATH"  # /usr/sbin/nginx

export GOPATH="${GOPATH:-/tmp/go}"
export PATH="$GOPATH/bin:$PATH"

if [ `uname` = "Darwin" ];then
  readlink="greadlink"
else
  readlink="readlink"
fi

common_no_force_renew() {
    certbot_test_no_force_renew \
        --authenticator standalone \
        --installer null \
        "$@"
}

common() {
    common_no_force_renew \
        --renew-by-default \
        "$@"
}

# We start a server listening on the port for the
# unrequested challenge to prevent regressions in #3601.
python -m SimpleHTTPServer $http_01_port &
python_server_pid=$!
common --domains le1.wtf --preferred-challenges tls-sni-01 auth
kill $python_server_pid
python -m SimpleHTTPServer $tls_sni_01_port &
python_server_pid=$!
common --domains le2.wtf --preferred-challenges http-01 run
kill $python_server_pid

common -a manual -d le.wtf auth --rsa-key-size 4096

export CSR_PATH="${root}/csr.der" KEY_PATH="${root}/key.pem" \
       OPENSSL_CNF=examples/openssl.cnf
./examples/generate-csr.sh le3.wtf
common auth --csr "$CSR_PATH" \
       --cert-path "${root}/csr/cert.pem" \
       --chain-path "${root}/csr/chain.pem"
openssl x509 -in "${root}/csr/cert.pem" -text
openssl x509 -in "${root}/csr/chain.pem" -text

common --domains le3.wtf install \
       --cert-path "${root}/csr/cert.pem" \
       --key-path "${root}/csr/key.pem"

CheckCertCount() {
    CERTCOUNT=`ls "${root}/conf/archive/le.wtf/cert"* | wc -l`
    if [ "$CERTCOUNT" -ne "$1" ] ; then
        echo Wrong cert count, not "$1" `ls "${root}/conf/archive/le.wtf/"*`
        exit 1
    fi
}

CheckCertCount 1
# This won't renew (because it's not time yet)
common_no_force_renew renew
CheckCertCount 1

# --renew-by-default is used, so renewal should occur
common renew
CheckCertCount 2

# This will renew because the expiry is less than 10 years from now
sed -i "4arenew_before_expiry = 4 years" "$root/conf/renewal/le.wtf.conf"
common_no_force_renew renew --rsa-key-size 2048
CheckCertCount 3

# The 4096 bit setting should persist to the first renewal, but be overriden in the second

size1=`wc -c ${root}/conf/archive/le.wtf/privkey1.pem | cut -d" " -f1`
size2=`wc -c ${root}/conf/archive/le.wtf/privkey2.pem | cut -d" " -f1`
size3=`wc -c ${root}/conf/archive/le.wtf/privkey3.pem | cut -d" " -f1`
# 4096 bit PEM keys are about ~3270 bytes, 2048 ones are about 1700 bytes
if [ "$size1" -lt 3000 ] || [ "$size2" -lt 3000 ] || [ "$size3" -gt 1800 ] ; then
    echo key sizes violate assumptions:
    ls -l "${root}/conf/archive/le.wtf/privkey"*
    exit 1
fi

# ECDSA
openssl ecparam -genkey -name secp384r1 -out "${root}/privkey-p384.pem"
SAN="DNS:ecdsa.le.wtf" openssl req -new -sha256 \
    -config "${OPENSSL_CNF:-openssl.cnf}" \
    -key "${root}/privkey-p384.pem" \
    -subj "/" \
    -reqexts san \
    -outform der \
    -out "${root}/csr-p384.der"
common auth --csr "${root}/csr-p384.der" \
    --cert-path "${root}/csr/cert-p384.pem" \
    --chain-path "${root}/csr/chain-p384.pem"
openssl x509 -in "${root}/csr/cert-p384.pem" -text | grep 'ASN1 OID: secp384r1'

# OCSP Must Staple
common auth --must-staple --domains "must-staple.le.wtf"
openssl x509 -in "${root}/conf/live/must-staple.le.wtf/cert.pem" -text | grep '1.3.6.1.5.5.7.1.24'

# revoke by account key
common revoke --cert-path "$root/conf/live/le.wtf/cert.pem"
# revoke renewed
common revoke --cert-path "$root/conf/live/le1.wtf/cert.pem"
# revoke by cert key
common revoke --cert-path "$root/conf/live/le2.wtf/cert.pem" \
       --key-path "$root/conf/live/le2.wtf/privkey.pem"

if type nginx;
then
    . ./certbot-nginx/tests/boulder-integration.sh
fi
