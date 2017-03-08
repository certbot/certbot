# Based on
# https://www.exratione.com/2014/03/running-nginx-as-a-non-root-user/
# https://github.com/exratione/non-root-nginx/blob/9a77f62e5d5cb9c9026fd62eece76b9514011019/nginx.conf

cat <<EOF
# This error log will be written regardless of server scope error_log
# definitions, so we have to set this here in the main scope.
#
# Even doing this, Nginx will still try to create the default error file, and
# log a non-fatal error when it fails. After that things will work, however.
error_log $root/error.log;

# The pidfile will be written to /var/run unless this is set.
pid $root/nginx.pid;

worker_processes 1;

events {
  worker_connections 1024;
}

http {
  # Set an array of temp, cache and log file options that will otherwise default to
  # restricted locations accessible only to root.
  client_body_temp_path $root/client_body;
  fastcgi_temp_path $root/fastcgi_temp;
  proxy_temp_path $root/proxy_temp;
  #scgi_temp_path $root/scgi_temp;
  #uwsgi_temp_path $root/uwsgi_temp;
  access_log $root/error.log;

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
    listen 8081;
    # IPv6.
    listen [::]:8081 default ipv6only=on;
    server_name nginx.wtf;

    root $root/webroot;

    location / {
      # First attempt to serve request as file, then as directory, then fall
      # back to index.html.
      try_files \$uri \$uri/ /index.html;
    }
  }
}
EOF
