#!/bin/sh

if [ "xxx$root" = "xxx" ];
then
    root="$(mktemp -d)"
    echo "Root integration tests directory: $root"
fi
store_flags="--config-dir $root/conf --work-dir $root/work"
store_flags="$store_flags --logs-dir $root/logs"
export root store_flags

letsencrypt_test () {
    # first three flags required, rest is handy defaults
    letsencrypt \
        --server "${SERVER:-http://localhost:4000/acme/new-reg}" \
        --no-verify-ssl \
        --dvsni-port 5001 \
        $store_flags \
        --text \
        --agree-eula \
        --email "" \
        --debug \
        -vvvvvvv \
        "$@"
}
