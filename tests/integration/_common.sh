# The -t is required on macOS. It provides a template file path for
# the kernel to use.
root=${root:-$(mktemp -d -t leitXXXX)}
echo "Root integration tests directory: $root"
config_dir="$root/conf"
https_port=5001
http_01_port=5002
sources="acme/,$(ls -dm certbot*/ | tr -d ' \n')"
export root config_dir https_port http_01_port sources
certbot_path="$(command -v certbot)"
# Flags that are added here will be added to Certbot calls within
# certbot_test_no_force_renew.
other_flags="--config-dir $config_dir --work-dir $root/work"
other_flags="$other_flags --logs-dir $root/logs"

certbot_test () {
    certbot_test_no_force_renew \
        --renew-by-default \
        "$@"
}

# Succeeds if Certbot version is at least the given version number and fails
# otherwise. This is useful for making sure Certbot has certain features
# available. The patch version is currently ignored.
#
# Arguments:
#   First argument is the minimum major version
#   Second argument is the minimum minor version
version_at_least () {
    # Certbot major and minor version (e.g. 0.30)
    major_minor=$("$certbot_path" --version 2>&1 | cut -d' ' -f2 | cut -d. -f1,2)
    major=$(echo "$major_minor" | cut -d. -f1)
    minor=$(echo "$major_minor" | cut -d. -f2)
    # Test that either the major version is greater or major version is equal
    # and minor version is greater than or equal to.
    [ \( "$major" -gt "$1" \) -o \( "$major" -eq "$1" -a "$minor" -ge "$2" \) ]
}

# Use local ACMEv2 endpoint if requested and SERVER isn't already set.
if [ "${BOULDER_INTEGRATION:-v1}" = "v2" -a -z "${SERVER:+x}" ]; then
    SERVER="http://localhost:4001/directory"
fi

# --no-random-sleep-on-renew was added in
# https://github.com/certbot/certbot/pull/6599 and first released in Certbot
# 0.30.0.
if version_at_least 0 30; then
  other_flags="$other_flags --no-random-sleep-on-renew"
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
        "$certbot_path" \
            --server "${SERVER:-http://localhost:4000/directory}" \
            --no-verify-ssl \
            --http-01-port $http_01_port \
            --tls-sni-01-port $https_port \
            --manual-public-ip-logging-ok \
            $other_flags \
            --non-interactive \
            --no-redirect \
            --agree-tos \
            --register-unsafely-without-email \
            --debug \
            -vv \
            "$@"
}
