import os
import getpass
import subprocess
import sys
import random
import shutil
import filecmp

import pytest
import ssl
from OpenSSL import crypto

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
    os.mkdir(root)
    return root


@pytest.fixture
def webroot(nginx_root):
    path = os.path.join(nginx_root, 'webroot')
    os.mkdir(path)
    with open(os.path.join(path, 'index.html'), 'w') as file:
        file.write('Hello World!')

    return path


@pytest.fixture
def other_port():
    return random.randint(6000,6999)


@pytest.fixture
def nginx_configs(nginx_root, webroot, tls_sni_01_port, http_01_port, other_port):
    config = '''\
# This error log will be written regardless of server scope error_log
# definitions, so we have to set this here in the main scope.
#
# Even doing this, Nginx will still try to create the default error file, and
# log a non-fatal error when it fails. After that things will work, however.
error_log {root}/error.log;

# The pidfile will be written to /var/run unless this is set.
pid {root}/nginx.pid;

user {user};

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

    root {webroot};

    location /.well-known/ {{
      return 404;
    }}

    return 301 https://$host$request_uri;
  }}

  server {{
    listen {other_port};
    listen [::]:{other_port};
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
           webroot=webroot,
           user=getpass.getuser(),
           http_01_port=http_01_port,
           tls_sni_01_port=tls_sni_01_port,
           other_port=other_port,
           default_server='default_server')

    nginx_conf_path = os.path.join(nginx_root, 'nginx.conf')
    nginx_conf_original_path = os.path.join(nginx_root, 'nginx-original.conf')
    with open(nginx_conf_path, 'w') as file:
        file.write(config)
    shutil.copy(nginx_conf_path, nginx_conf_original_path)

    return nginx_conf_path, nginx_conf_original_path


@pytest.fixture(autouse=True)
def nginx(nginx_configs, webroot, http_01_port):
    (nginx_config, _) = nginx_configs
    assert webroot
    process = subprocess.Popen(['nginx', '-c', nginx_config, '-g', 'daemon off;'], stdout=sys.stdout, stderr=sys.stderr)
    try:
        assert not process.poll()
        misc.check_until_timeout('http://localhost:{0}'.format(http_01_port))
        yield
    finally:
        process.terminate()
        process.wait()


@pytest.fixture
def assert_deployment_and_rollback(workspace, nginx_root, nginx_configs,
                                   tls_sni_01_port, certbot_test_no_force_renew):
    def func(certname):
        server_cert = ssl.get_server_certificate(('localhost', tls_sni_01_port))
        with open(os.path.join(workspace, 'conf/live/{0}/cert.pem'.format(certname)), 'r') as file:
            certbot_cert = file.read()

        assert server_cert == certbot_cert

        command = ['--authenticator', 'nginx', '--installer', 'nginx',
                   '--nginx-server-root', nginx_root,
                   'rollback', '--checkpoints', '1']
        certbot_test_no_force_renew(command)
        (nginx_config, nginx_original_config) = nginx_configs

        assert filecmp.cmp(nginx_config, nginx_original_config)

    return func
