#!/usr/bin/env bash
# Based on
# https://www.exratione.com/2014/03/running-nginx-as-a-non-root-user/
# https://github.com/exratione/non-root-nginx/blob/9a77f62e5d5cb9c9026fd62eece76b9514011019/nginx.conf

# USAGE: ./boulder-integration.conf.sh /path/to/root cert.key cert.pem >> nginx.conf

ROOT=$1
CERT_KEY_PATH=$2
CERT_PATH=$3

cat <<EOF
# This error log will be written regardless of server scope error_log
# definitions, so we have to set this here in the main scope.
#
# Even doing this, Nginx will still try to create the default error file, and
# log a non-fatal error when it fails. After that things will work, however.
error_log $ROOT/error.log;

# The pidfile will be written to /var/run unless this is set.
pid $ROOT/nginx.pid;

worker_processes 1;

events {
  worker_connections 1024;
}

http {
  # Set an array of temp, cache and log file options that will otherwise default to
  # restricted locations accessible only to root.
  client_body_temp_path $ROOT/client_body;
  fastcgi_temp_path $ROOT/fastcgi_temp;
  proxy_temp_path $ROOT/proxy_temp;
  #scgi_temp_path $ROOT/scgi_temp;
  #uwsgi_temp_path $ROOT/uwsgi_temp;
  access_log $ROOT/error.log;

  # This should be turned off in a Virtualbox VM, as it can cause some
  # interesting issues with data corruption in delivered files.
  sendfile off;

  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;

  #include /etc/nginx/mime.types;
  index index.html index.htm index.php;

  log_format   main '\$remote_addr - \$remote_user [\$time_local] \$status '
    '"\$request" \$body_bytes_sent "\$http_referer" '
    '"\$http_user_agent" "\$http_x_forwarded_for"';

  default_type application/octet-stream;

  server {
    # IPv4.
    listen 5002 $default_server;
    # IPv6.
    listen [::]:5002 $default_server;
    server_name nginx.wtf nginx2.wtf;

    root $ROOT/webroot;

    location / {
      # First attempt to serve request as file, then as directory, then fall
      # back to index.html.
      try_files \$uri \$uri/ /index.html;
    }
  }

  server {
    listen 5002;
    listen [::]:5002;
    server_name nginx3.wtf;

    root $ROOT/webroot;

    location /.well-known/ {
      return 404;
    }

    return 301 https://\$host\$request_uri;
  }

  server {
    listen 8082;
    listen [::]:8082;
    server_name nginx4.wtf nginx5.wtf;
  }

  server {
    listen 5002;
    listen [::]:5002;
    listen 5001 ssl;
    listen [::]:5001 ssl;
    if (\$scheme != "https") {
      return 301 https://\$host\$request_uri;
    }
    server_name nginx6.wtf nginx7.wtf;

    ssl_certificate ${CERT_PATH};
    ssl_certificate_key ${CERT_KEY_PATH};
  }
}
EOF
