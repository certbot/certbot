#!/bin/sh -xe

# prerequisite: apt-get install --no-install-recommends nginx-light openssl

if [ "xxx$root" = "xxx" ];
then
    root="$(mktemp -d)"
fi
export root

export PATH="/usr/sbin:$PATH"  # /usr/sbin/nginx

echo "\nRoot integration tests directory: $root"
store_flags="--config-dir $root/conf --work-dir $root/work"
store_flags="$store_flags --logs-dir $root/logs"

nginx_root="$root/nginx"
mkdir $nginx_root
root="$nginx_root" ./tests/nginx.conf.sh > $nginx_root/nginx.conf

killall nginx || true
nginx -c $nginx_root/nginx.conf

common() {
    # first three flags required, rest is handy defaults
    letsencrypt \
        --server "${SERVER:-http://localhost:4000/acme/new-reg}" \
        --no-verify-ssl \
        --dvsni-port 5001 \
        $store_flags \
        --text \
        --agree-eula \
        --email "" \
        -vvvvvvv "$@"
}

test_nginx() {
    common --configurator nginx \
           --nginx-server-root $nginx_root \
           "$@"
}

test_nginx --domains nginx.wtf run
echo | openssl s_client -connect localhost:5001 \
    | openssl x509 -out $root/nginx.pem
diff -q $root/nginx.pem $root/conf/live/nginx.wtf/cert.pem

# note: not reached if anything above fails, hence "killall" at the
# top
nginx -c $nginx_root/nginx.conf -s stop
