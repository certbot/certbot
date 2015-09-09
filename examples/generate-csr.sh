#!/bin/sh
# This script generates a simple SAN CSR to be used with Let's Encrypt
# CA. Mostly intended for "auth --csr" testing, but, since it's easily
# auditable, feel free to adjust it and use it on your production web
# server.

if [ "$#" -lt 1 ]
then
  echo "Usage: $0 domain [domain...]" >&2
  exit 1
fi

domains="DNS:$1"
shift
for x in "$@"
do
  domains="$domains,DNS:$x"
done

SAN="$domains" openssl req -config "${OPENSSL_CNF:-openssl.cnf}" \
  -new -nodes -subj '/' -reqexts san \
  -out "${CSR_PATH:-csr.der}" \
  -keyout "${KEY_PATH:-key.pem}" \
  -newkey rsa:2048 \
  -outform DER
# 512 or 1024 too low for Boulder, 2048 is smallest for tests

echo "You can now run: letsencrypt auth --csr ${CSR_PATH:-csr.der}"
