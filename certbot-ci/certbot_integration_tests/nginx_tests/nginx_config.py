"""General test purpose nginx configuration generator."""
import datetime
import getpass
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
# TODO: once mypy has cryptography types bundled, type: ignore can be removed.
# See https://github.com/python/typeshed/tree/master/third_party/2/cryptography
from cryptography.hazmat.primitives import serialization, hashes  # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa


def construct_nginx_config(nginx_root, nginx_webroot, key_path, cert_path, http_port, https_port,
                           other_port, default_server, wtf_prefix='le'):
    """
    This method returns a full nginx configuration suitable for integration tests.
    :param nginx_root: nginx root configuration path
    :param nginx_webroot: nginx webroot path
    :param key_path: the path to the SSL key
    :param cert_path: the path to the SSL certificate
    :param http_port: HTTP port to listen on
    :param https_port: HTTPS port to listen on
    :param other_port: other HTTP port to listen on
    :param default_server: set as 'default_server' to make 'nginx.conf'
                           the default server, empty string otherwise
    :return: a string containing the full nginx configuration
    """
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
           default_server=default_server, wtf_prefix=wtf_prefix,
           cert_path=cert_path, key_path=key_path)


def create_self_signed_certificate(nginx_root):
    """Generate a self-signed certificate for nginx.
    :param nginx_root: path of folder where to put the certificate
    :return: tuple containing the key path and certificate path
    :rtype: `tuple`
    """
    # Generate key
    # See comment on cryptography import about type: ignore
    private_key = rsa.generate_private_key(  # type: ignore
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'nginx.wtf')
    ])
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        1
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).sign(private_key, hashes.SHA256(), default_backend())

    key_path = os.path.join(nginx_root, 'cert.key')
    with open(key_path, 'wb') as file_handle:
        file_handle.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    cert_path = os.path.join(nginx_root, 'cert.pem')
    with open(cert_path, 'wb') as file_handle:
        file_handle.write(certificate.public_bytes(serialization.Encoding.PEM))

    return key_path, cert_path
