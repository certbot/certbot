server {
  server_name ssl.both.com;
}

# a duplicate vhost
server {
  server_name ssl.both.com;
}

# not a duplicate, but still covers ssl.both.com
server {
  server_name *.both.com;
}

# https and covers ssl.both.com
server {
  server_name *.both.com;
  listen 5001 ssl;

  ssl_certificate      cert.pem;
  ssl_certificate_key  cert.key;
}
