# The -t is required on macOS. It provides a template file path for
# the kernel to use.
root=${root:-$(mktemp -d -t leitXXXX)}
echo "Root integration tests directory: $root"
store_flags="--config-dir $root/conf --work-dir $root/work"
store_flags="$store_flags --logs-dir $root/logs"
tls_sni_01_port=5001
http_01_port=5002
export root store_flags tls_sni_01_port http_01_port

certbot_test () {
    certbot_test_no_force_renew \
        --renew-by-default \
        "$@"
}

certbot_test_no_force_renew () {
    certbot \
        --server "${SERVER:-http://localhost:4000/directory}" \
        --no-verify-ssl \
        --tls-sni-01-port $tls_sni_01_port \
        --http-01-port $http_01_port \
        --manual-public-ip-logging-ok \
        $store_flags \
        --non-interactive \
        --no-redirect \
        --agree-tos \
        --register-unsafely-without-email \
        --debug \
        -vv \
        "$@"
}
