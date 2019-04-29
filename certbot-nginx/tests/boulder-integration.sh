#!/bin/bash -xe
# prerequisite: apt-get install --no-install-recommends nginx-light openssl

. ./tests/integration/_common.sh

export PATH="/usr/sbin:$PATH"  # /usr/sbin/nginx
nginx_root="$root/nginx"
mkdir $nginx_root

# Generate self-signed certificate for Nginx
openssl req -new -newkey rsa:2048 -days 1 -nodes -x509 \
    -keyout $nginx_root/cert.key -out $nginx_root/cert.pem -subj "/CN=nginx.wtf"

reload_nginx () {
    original=$(./certbot-nginx/tests/boulder-integration.conf.sh $nginx_root $nginx_root/cert.key $nginx_root/cert.pem)
    nginx_conf="$nginx_root/nginx.conf"
    echo "$original" > $nginx_conf

    killall nginx || true
    nginx -c $nginx_root/nginx.conf
}

certbot_test_nginx () {
    certbot_test \
        --authenticator nginx \
        --installer nginx \
        --nginx-server-root $nginx_root \
        "$@"
}

test_deployment_and_rollback() {
    # Arguments: certname
    echo | openssl s_client -connect localhost:5001 \
        | openssl x509 -out $root/nginx.pem
    diff -q $root/nginx.pem "$root/conf/live/$1/cert.pem"

    certbot_test_nginx rollback --checkpoints 9001
    diff -q <(echo "$original") $nginx_conf
}

export default_server="default_server"
nginx -v
reload_nginx
certbot_test_nginx --domains nginx.wtf run
test_deployment_and_rollback nginx.wtf
certbot_test_nginx --domains nginx2.wtf --preferred-challenges http
test_deployment_and_rollback nginx2.wtf
# Overlapping location block and server-block-level return 301
certbot_test_nginx --domains nginx3.wtf --preferred-challenges http
test_deployment_and_rollback nginx3.wtf
# No matching server block; default_server exists
certbot_test_nginx --domains nginx4.wtf --preferred-challenges http
test_deployment_and_rollback nginx4.wtf
# No matching server block; default_server does not exist
export default_server=""
reload_nginx
if nginx -c $nginx_root/nginx.conf -T 2>/dev/null | grep "default_server"; then
    echo "Failed to remove default_server"
    exit 1
fi
certbot_test_nginx --domains nginx5.wtf --preferred-challenges http
test_deployment_and_rollback nginx5.wtf
# Mutiple domains, mix of matching and not
certbot_test_nginx --domains nginx6.wtf,nginx7.wtf --preferred-challenges http
test_deployment_and_rollback nginx6.wtf

# note: not reached if anything above fails, hence "killall" at the
# top
nginx -c $nginx_root/nginx.conf -s stop

coverage report --fail-under 72 --include 'certbot-nginx/*' --show-missing
