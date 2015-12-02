#!/bin/sh

if [ "xxx$root" = "xxx" ];
then
    # The -t is required on OS X. It provides a template file path for
    # the kernel to use.
    root="$(mktemp -d -t leitXXXX)"
    echo "Root integration tests directory: $root"
fi
store_flags="--config-dir $root/conf --work-dir $root/work"
store_flags="$store_flags --logs-dir $root/logs"
export root store_flags

letsencrypt_test () {
    letsencrypt \
        --server "${SERVER:-http://localhost:4000/directory}" \
        --no-verify-ssl \
        --tls-sni-01-port 5001 \
        --http-01-port 5002 \
        --manual-test-mode \
        $store_flags \
        --text \
        --no-redirect \
        --agree-tos \
        --register-unsafely-without-email \
        --renew-by-default \
        --debug \
        -vvvvvvv \
        "$@"
}
