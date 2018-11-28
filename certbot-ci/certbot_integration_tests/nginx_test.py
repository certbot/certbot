import os
import shutil
import subprocess

import pytest

from certbot_integration_tests.utils import misc

@pytest.fixture
def certbot_test_nginx(certbot_test):
    def func(args):
        command = ['--authenticator', 'nginx', '--installer', 'nginx']
        command.extend(args)
        return certbot_test(command)

    return func


@pytest.fixture
def nginx_root(workspace):
    root = os.path.join(workspace, 'nginx')
    try:
        os.mkdir(root)
        yield root
    finally:
        shutil.rmtree(root)


@pytest.fixture
def nginx_config(nginx_root, tls_sni_01_port, http_01_port):
    config = '''\
# This error log will be written regardless of server scope error_log
# definitions, so we have to set this here in the main scope.
#
# Even doing this, Nginx will still try to create the default error file, and
# log a non-fatal error when it fails. After that things will work, however.
error_log {root}/error.log;

# The pidfile will be written to /var/run unless this is set.
pid {root}/nginx.pid;

worker_processes 1;

events {{
  worker_connections 1024;
}}

http {{
  # Set an array of temp, cache and log file options that will otherwise default to
  # restricted locations accessible only to root.
  client_body_temp_path {root}/client_body;
  fastcgi_temp_path {root}/fastcgi_temp;
  proxy_temp_path {root}/proxy_temp;
  #scgi_temp_path {root}/scgi_temp;
  #uwsgi_temp_path {root}/uwsgi_temp;
  access_log {root}/error.log;

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
    listen {http_01_port} {default_server};
    # IPv6.
    listen [::]:{http_01_port} {default_server};
    server_name nginx.wtf nginx2.wtf;

    root {root}/webroot;

    location / {{
      # First attempt to serve request as file, then as directory, then fall
      # back to index.html.
      try_files $uri $uri/ /index.html;
    }}
  }}

  server {{
    listen {http_01_port};
    listen [::]:{http_01_port};
    server_name nginx3.wtf;

    root {root}/webroot;

    location /.well-known/ {{
      return 404;
    }}

    return 301 https://$host$request_uri;
  }}

  server {{
    listen 8082;
    listen [::]:8082;
    server_name nginx4.wtf nginx5.wtf;
  }}

  server {{
    listen {http_01_port};
    listen [::]:{http_01_port};
    listen {tls_sni_01_port} ssl;
    listen [::]:{tls_sni_01_port} ssl;
    if ($scheme != "https") {{
      return 301 https://$host$request_uri;
    }}
    server_name nginx6.wtf nginx7.wtf;
  }}
}}
'''.format(root=nginx_root,
           http_01_port=http_01_port,
           tls_sni_01_port=tls_sni_01_port,
           default_server='default_server')


@pytest.fixture(autouse=True)
def nginx(nginx_config, http_01_port):
    process = subprocess.Popen(['nginx', '-c', nginx_config])
    try:
        assert not process.poll()
        misc.check_until_timeout('http://localhost:{0}'.format(http_01_port))
        yield
    finally:
        process.terminate()
        process.wait()


def test_all(workspace):
    assert workspace
