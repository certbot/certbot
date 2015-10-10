#!/bin/sh -xe
# prerequisite: apt-get install --no-install-recommends nginx-light openssl

. ./tests/integration/_common.sh

export PATH="/usr/sbin:$PATH"  # /usr/sbin/nginx
nginx_root="$root/nginx"
mkdir $nginx_root
run_with () {
  directives=$(shift)
  echo "DIRECTIVES $directives"
  export directives
  root="$nginx_root" ./letsencrypt-nginx/tests/boulder-integration.conf.sh > $nginx_root/nginx.conf

  killall nginx || true
  nginx -c $nginx_root/nginx.conf

  letsencrypt_test_nginx () {
      letsencrypt_test \
          --configurator nginx \
          --nginx-server-root $nginx_root \
          "$@"
  }

  letsencrypt_test_nginx --domains nginx.wtf run
  echo | openssl s_client -connect localhost:5001 \
      | openssl x509 -out $root/nginx.pem
  diff -q $root/nginx.pem $root/conf/live/nginx.wtf/cert.pem

  # note: not reached if anything above fails, hence "killall" at the
  # top
  nginx -c $nginx_root/nginx.conf -s stop
}

# Run with and without server_names_hash_bucket_size, to ensure that the
# configurator correctly adds it when it is needed and doesn't add it when
# it's already there.
run_with ""
run_with "server_names_hash_bucket_size 128;"
