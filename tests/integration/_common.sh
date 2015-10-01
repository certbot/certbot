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
        --dvsni-port 5001 \
        --simple-http-port 5001 \
        --manual-test-mode \
        $store_flags \
        --text \
        --agree-eula \
        --agree-tos \
        --email "" \
        --renew-by-default \
        --debug \
        -vvvvvvv \
        "$@"
}
