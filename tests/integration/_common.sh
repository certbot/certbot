# The -t is required on macOS. It provides a template file path for
# the kernel to use.
root=${root:-$(mktemp -d -t leitXXXX)}
echo "Root integration tests directory: $root"
config_dir="$root/conf"
store_flags="--config-dir $config_dir --work-dir $root/work"
store_flags="$store_flags --logs-dir $root/logs"
tls_sni_01_port=5001
http_01_port=5002
sources="acme/,$(ls -dm certbot*/ | tr -d ' \n')"
export root config_dir store_flags tls_sni_01_port http_01_port sources

certbot_test () {
    certbot_test_no_force_renew \
        --renew-by-default \
        "$@"
}

# Use local ACMEv2 endpoint if requested and SERVER isn't already set.
if [ "${BOULDER_INTEGRATION:-v1}" = "v2" -a -z "${SERVER:+x}" ]; then
    SERVER="http://localhost:4001/directory"
fi

certbot_test_no_force_renew () {
    omit_patterns="*/*.egg-info/*,*/dns_common*,*/setup.py,*/test_*,*/tests/*"
    omit_patterns="$omit_patterns,*_test.py,*_test_*,certbot-apache/*"
    omit_patterns="$omit_patterns,certbot-compatibility-test/*,certbot-dns*/"
    omit_patterns="$omit_patterns,certbot-nginx/certbot_nginx/parser_obj.py"
    coverage run \
        --append \
        --source $sources \
        --omit $omit_patterns \
        $(command -v certbot) \
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
            --no-random-sleep-on-renew \
            "$@"
}
