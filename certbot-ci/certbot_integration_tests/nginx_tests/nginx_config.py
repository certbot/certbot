"""General purpose nginx test configuration generator."""
import getpass

import pkg_resources


def construct_nginx_config(nginx_root, nginx_webroot, http_port, https_port, other_port,
                           default_server, key_path=None, cert_path=None, wtf_prefix='le'):
    """
    This method returns a full nginx configuration suitable for integration tests.
    :param str nginx_root: nginx root configuration path
    :param str nginx_webroot: nginx webroot path
    :param int http_port: HTTP port to listen on
    :param int https_port: HTTPS port to listen on
    :param int other_port: other HTTP port to listen on
    :param bool default_server: True to set a default server in nginx config, False otherwise
    :param str key_path: the path to a SSL key
    :param str cert_path: the path to a SSL certificate
    :param str wtf_prefix: the prefix to use in all domains handled by this nginx config
    :return: a string containing the full nginx configuration
    :rtype: str
    """
    key_path = key_path if key_path \
        else pkg_resources.resource_filename('certbot_integration_tests', 'assets/key.pem')
    cert_path = cert_path if cert_path \
        else pkg_resources.resource_filename('certbot_integration_tests', 'assets/cert.pem')
    return '''\
# This error log will be written regardless of server scope error_log
# definitions, so we have to set this here in the main scope.
#
# Even doing this, Nginx will still try to create the default error file, and
# log a non-fatal error when it fails. After that things will work, however.
error_log {nginx_root}/error.log;

# The pidfile will be written to /var/run unless this is set.
pid {nginx_root}/nginx.pid;

user {user};
worker_processes 1;

events {{
  worker_connections 1024;
}}

http {{
  # Set an array of temp, cache and log file options that will otherwise default to
  # restricted locations accessible only to root.
  client_body_temp_path {nginx_root}/client_body;
  fastcgi_temp_path {nginx_root}/fastcgi_temp;
  proxy_temp_path {nginx_root}/proxy_temp;
  #scgi_temp_path {nginx_root}/scgi_temp;
  #uwsgi_temp_path {nginx_root}/uwsgi_temp;
  access_log {nginx_root}/error.log;
  
  # This should be turned off in a Virtualbox VM, as it can cause some
  # interesting issues with data corruption in delivered files.
  sendfile off;
  
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  
  #include /etc/nginx/mime.types;
  index index.html index.htm index.php;
  
  log_format   main '$remote_addr - $remote_user [$time_local] $status '
    '"$request" $body_bytes_sent "$http_referer" '
    '"$http_user_agent" "$http_x_forwarded_for"';
    
  default_type application/octet-stream;
  
  server {{
    # IPv4.
    listen {http_port} {default_server};
    # IPv6.
    listen [::]:{http_port} {default_server};
    server_name nginx.{wtf_prefix}.wtf nginx2.{wtf_prefix}.wtf;
    
    root {nginx_webroot};
    
    location / {{
      # First attempt to serve request as file, then as directory, then fall
      # back to index.html.
      try_files $uri $uri/ /index.html;
    }}
  }}
  
  server {{
    listen {http_port};
    listen [::]:{http_port};
    server_name nginx3.{wtf_prefix}.wtf;
    
    root {nginx_webroot};
    
    location /.well-known/ {{
      return 404;
    }}
    
    return 301 https://$host$request_uri;
  }}
  
  server {{
    listen {other_port};
    listen [::]:{other_port};
    server_name nginx4.{wtf_prefix}.wtf nginx5.{wtf_prefix}.wtf;
  }}
  
  server {{
    listen {http_port};
    listen [::]:{http_port};
    listen {https_port} ssl;
    listen [::]:{https_port} ssl;
    if ($scheme != "https") {{
      return 301 https://$host$request_uri;
    }}
    server_name nginx6.{wtf_prefix}.wtf nginx7.{wtf_prefix}.wtf;

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
  }}
}}
'''.format(nginx_root=nginx_root, nginx_webroot=nginx_webroot, user=getpass.getuser(),
           http_port=http_port, https_port=https_port, other_port=other_port,
           default_server='default_server' if default_server else '', wtf_prefix=wtf_prefix,
           key_path=key_path, cert_path=cert_path)
