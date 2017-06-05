#!/bin/bash
# Simple integration test. Make sure to activate virtualenv beforehand
# (source venv/bin/activate) and that you are running Boulder test
# instance (see ./boulder-fetch.sh).
#
# Environment variables:
#   SERVER: Passed as "certbot --server" argument.
#
# Note: this script is called by Boulder integration test suite!

set -eux

. ./tests/integration/_common.sh
export PATH="$PATH:/usr/sbin"  # /usr/sbin/nginx

cleanup_and_exit() {
    EXIT_STATUS=$?
    if SERVER_STILL_RUNNING=`ps -p $python_server_pid -o pid=`
    then
        echo Kill server subprocess, left running by abnormal exit
        kill $SERVER_STILL_RUNNING
    fi
    # Dump boulder logs in case they contain useful debugging information.
    : "------------------ ------------------ ------------------"
    : "------------------ begin boulder logs ------------------"
    : "------------------ ------------------ ------------------"
    docker logs boulder_boulder_1
    : "------------------ ------------------ ------------------"
    : "------------------  end boulder logs  ------------------"
    : "------------------ ------------------ ------------------"
    exit $EXIT_STATUS
}

trap cleanup_and_exit EXIT

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

export HOOK_TEST="/tmp/hook$$"
CheckHooks() {
    EXPECTED="/tmp/expected$$"
    if [ $(head -n1 $HOOK_TEST) = "wtf.pre" ]; then
        echo "wtf.pre" > "$EXPECTED"
        echo "wtf2.pre" >> "$EXPECTED"
        echo "renew" >> "$EXPECTED"
        echo "renew" >> "$EXPECTED"
        echo "wtf.post" >> "$EXPECTED"
        echo "wtf2.post" >> "$EXPECTED"
    else
        echo "wtf2.pre" > "$EXPECTED"
        echo "wtf.pre" >> "$EXPECTED"
        echo "renew" >> "$EXPECTED"
        echo "renew" >> "$EXPECTED"
        echo "wtf2.post" >> "$EXPECTED"
        echo "wtf.post" >> "$EXPECTED"
    fi

    if ! cmp --quiet "$EXPECTED" "$HOOK_TEST" ; then
        echo Hooks did not run as expected\; got
        cat "$HOOK_TEST"
        echo Expected
        cat "$EXPECTED"
    fi
    rm "$HOOK_TEST"
}

# test for regressions of #4719
get_num_tmp_files() {
    ls -1 /tmp | wc -l
}
num_tmp_files=$(get_num_tmp_files)
common --csr / && echo expected error && exit 1 || true
common --help
common --help all
common --version
if [ $(get_num_tmp_files) -ne $num_tmp_files ]; then
    echo "New files or directories created in /tmp!"
    exit 1
fi

# We start a server listening on the port for the
# unrequested challenge to prevent regressions in #3601.
python ./tests/run_http_server.py $http_01_port &
python_server_pid=$!

common --domains le1.wtf --preferred-challenges tls-sni-01 auth \
       --pre-hook 'echo wtf.pre >> "$HOOK_TEST"' \
       --post-hook 'echo wtf.post >> "$HOOK_TEST"'\
       --renew-hook 'echo renew >> "$HOOK_TEST"'
kill $python_server_pid
python ./tests/run_http_server.py $tls_sni_01_port &
python_server_pid=$!
common --domains le2.wtf --preferred-challenges http-01 run \
       --pre-hook 'echo wtf.pre >> "$HOOK_TEST"' \
       --post-hook 'echo wtf.post >> "$HOOK_TEST"'\
       --renew-hook 'echo renew >> "$HOOK_TEST"'
kill $python_server_pid

common certonly -a manual -d le.wtf --rsa-key-size 4096 \
    --manual-auth-hook ./tests/manual-http-auth.sh \
    --manual-cleanup-hook ./tests/manual-http-cleanup.sh \
    --pre-hook 'echo wtf2.pre >> "$HOOK_TEST"' \
    --post-hook 'echo wtf2.post >> "$HOOK_TEST"'

common certonly -a manual -d dns.le.wtf --preferred-challenges dns,tls-sni \
    --manual-auth-hook ./tests/manual-dns-auth.sh

common certonly --cert-name newname -d newname.le.wtf

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
    CERTCOUNT=`ls "${root}/conf/archive/$1/cert"* | wc -l`
    if [ "$CERTCOUNT" -ne "$2" ] ; then
        echo Wrong cert count, not "$2" `ls "${root}/conf/archive/$1/"*`
        exit 1
    fi
}

CheckCertCount "le.wtf" 1
# This won't renew (because it's not time yet)
common_no_force_renew renew
CheckCertCount "le.wtf" 1

# renew using HTTP manual auth hooks
common renew --cert-name le.wtf --authenticator manual
CheckCertCount "le.wtf" 2

# renew using DNS manual auth hooks
common renew --cert-name dns.le.wtf --authenticator manual
CheckCertCount "dns.le.wtf" 2

# This will renew because the expiry is less than 10 years from now
sed -i "4arenew_before_expiry = 4 years" "$root/conf/renewal/le.wtf.conf"
common_no_force_renew renew --rsa-key-size 2048
CheckCertCount "le.wtf" 3

# The 4096 bit setting should persist to the first renewal, but be overridden in the second

size1=`wc -c ${root}/conf/archive/le.wtf/privkey1.pem | cut -d" " -f1`
size2=`wc -c ${root}/conf/archive/le.wtf/privkey2.pem | cut -d" " -f1`
size3=`wc -c ${root}/conf/archive/le.wtf/privkey3.pem | cut -d" " -f1`
# 4096 bit PEM keys are about ~3270 bytes, 2048 ones are about 1700 bytes
if [ "$size1" -lt 3000 ] || [ "$size2" -lt 3000 ] || [ "$size3" -gt 1800 ] ; then
    echo key sizes violate assumptions:
    ls -l "${root}/conf/archive/le.wtf/privkey"*
    exit 1
fi

# --renew-by-default is used, so renewal should occur
[ -f "$HOOK_TEST" ] && rm -f "$HOOK_TEST"
common renew
CheckCertCount "le.wtf" 4
CheckHooks

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

# Get new certs to test revoke with a reason, by account and by cert key
common --domains le1.wtf
common revoke --cert-path "$root/conf/live/le1.wtf/cert.pem" \
    --reason cessationOfOperation
common --domains le2.wtf
common revoke --cert-path "$root/conf/live/le2.wtf/cert.pem" \
    --key-path "$root/conf/live/le2.wtf/privkey.pem" \
    --reason keyCompromise

common unregister

# Most CI systems set this variable to true.
# If the tests are running as part of CI, Nginx should be available.
if ${CI:-false} || type nginx;
then
    . ./certbot-nginx/tests/boulder-integration.sh
fi
