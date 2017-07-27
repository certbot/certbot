#!/bin/sh -xe
# prerequisite: apt-get install --no-install-recommends nginx-light openssl

. ./tests/integration/_common.sh

export PATH="/usr/sbin:$PATH"  # /usr/sbin/nginx
nginx_root="$root/nginx"
mkdir $nginx_root
original=$(root="$nginx_root" ./certbot-nginx/tests/boulder-integration.conf.sh)
nginx_conf="$nginx_root/nginx.conf"
echo "$original" > $nginx_conf


killall nginx || true
nginx -c $nginx_root/nginx.conf

certbot_test_nginx () {
    certbot_test \
        --authenticator nginx \
        --installer nginx \
        --nginx-server-root $nginx_root \
        "$@"
}

certbot_test_nginx --domains nginx.wtf run
echo | openssl s_client -connect localhost:5001 \
    | openssl x509 -out $root/nginx.pem
diff -q $root/nginx.pem $root/conf/live/nginx.wtf/cert.pem

certbot_test_nginx rollback --checkpoints 9001
diff -q <(echo "$original") $nginx_conf

# note: not reached if anything above fails, hence "killall" at the
# top
nginx -c $nginx_root/nginx.conf -s stop
