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
    letsencrypt_test_no_force_renew \
        --renew-by-default \
        "$@"
}

letsencrypt_test_no_force_renew () {
    letsencrypt \
        --server "${SERVER:-http://localhost:4000/directory}" \
        --no-verify-ssl \
        --tls-sni-01-port 5001 \
        --http-01-port 5002 \
        --manual-test-mode \
        $store_flags \
        --non-interactive \
        --no-redirect \
        --agree-tos \
        --register-unsafely-without-email \
        --debug \
        -vvvvvvv \
        "$@"
}
