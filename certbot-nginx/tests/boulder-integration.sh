#!/bin/sh -xe
# prerequisite: apt-get install --no-install-recommends nginx-light openssl

. ./tests/integration/_common.sh

export PATH="/usr/sbin:$PATH"  # /usr/sbin/nginx
nginx_root="$root/nginx"
mkdir $nginx_root
root="$nginx_root" ./certbot-nginx/tests/boulder-integration.conf.sh > $nginx_root/nginx.conf

killall nginx || true
nginx -c $nginx_root/nginx.conf

certbot_test_nginx () {
    certbot_test \
        --configurator nginx \
        --nginx-server-root $nginx_root \
        "$@"
}

certbot_test_nginx --domains nginx.wtf run
echo | openssl s_client -connect localhost:5001 \
    | openssl x509 -out $root/nginx.pem
diff -q $root/nginx.pem $root/conf/live/nginx.wtf/cert.pem

# note: not reached if anything above fails, hence "killall" at the
# top
nginx -c $nginx_root/nginx.conf -s stop
