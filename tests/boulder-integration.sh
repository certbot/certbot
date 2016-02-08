#!/bin/sh -xe
# Simple integration test. Make sure to activate virtualenv beforehand
# (source venv/bin/activate) and that you are running Boulder test
# instance (see ./boulder-start.sh).
#
# Environment variables:
#   SERVER: Passed as "letsencrypt --server" argument.
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

common() {
    letsencrypt_test \
        --authenticator standalone \
        --installer null \
        "$@"
}

common_no_force_renew() {
    letsencrypt_test_no_force_renew \
        --authenticator standalone \
        --installer null \
        "$@"
}

common --domains le1.wtf --standalone-supported-challenges tls-sni-01 auth
common --domains le2.wtf --standalone-supported-challenges http-01 run
common -a manual -d le.wtf auth

export CSR_PATH="${root}/csr.der" KEY_PATH="${root}/key.pem" \
       OPENSSL_CNF=examples/openssl.cnf
./examples/generate-csr.sh le3.wtf
common auth --csr "$CSR_PATH" \
       --cert-path "${root}/csr/cert.pem" \
       --chain-path "${root}/csr/chain.pem"
openssl x509 -in "${root}/csr/0000_cert.pem" -text
openssl x509 -in "${root}/csr/0000_chain.pem" -text

common --domains le3.wtf install \
       --cert-path "${root}/csr/cert.pem" \
       --key-path "${root}/csr/key.pem"

CheckCertCount() {
    CERTCOUNT=`ls "${root}/conf/archive/le.wtf/"* | wc -l`
    if [ "$CERTCOUNT" -ne "$1" ] ; then
        echo Wrong cert count, not "$1" `ls "${root}/conf/archive/le.wtf/"*`
        exit 1
    fi
}

CheckCertCount 4
# This won't renew (because it's not time yet)
common_no_force_renew --authenticator standalone --installer null renew -tvv
CheckCertCount 4

# This will renew because the expiry is less than 10 years from now
#sed -i "4arenew_before_expiry = 10 years" "$root/conf/renewal/le1.wtf.conf"
common_no_force_renew --authenticator standalone --installer null renew --renew-by-default
CheckCertCount 8

# Check Param setting in renewal...
common_no_force_renew --authenticator standalone --installer null renew --renew-by-default
CheckCertCount 12

# The 4096 bit setting should persist to the first renewal, but be overriden in the second
size2=`wc -c ${root}/conf/archive/le.wtf/privkey2.pem | cut -d" " -f1`
size3=`wc -c ${root}/conf/archive/le.wtf/privkey3.pem | cut -d" " -f1`
#if ! [ "$size3" -lt "$size2" ] ; then
#    echo "key size failure:"
#    ls -l ${root}/conf/archive/le.wtf/
#    exit 1
#fi


# dir="$root/conf/archive/le1.wtf"
# for x in cert chain fullchain privkey;
# do
#     latest="$(ls -1t $dir/ | grep -e "^${x}" | head -n1)"
#     live="$($readlink -f "$root/conf/live/le1.wtf/${x}.pem")"
#     [ "${dir}/${latest}" = "$live" ]  # renewer fails this test
# done

# revoke by account key
common revoke --cert-path "$root/conf/live/le.wtf/cert.pem"
# revoke renewed
common revoke --cert-path "$root/conf/live/le1.wtf/cert.pem"
# revoke by cert key
common revoke --cert-path "$root/conf/live/le2.wtf/cert.pem" \
       --key-path "$root/conf/live/le2.wtf/privkey.pem"

if type nginx;
then
    . ./letsencrypt-nginx/tests/boulder-integration.sh
fi
