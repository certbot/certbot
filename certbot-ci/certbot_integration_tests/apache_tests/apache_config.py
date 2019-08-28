import shutil
import subprocess
import os

import pkg_resources
import getpass


def construct_apache_config_dir(apache_root, http_port, https_port, key_path=None,
                                cert_path=None, wtf_prefix='le'):
    config_path = os.path.join(apache_root, 'config')
    shutil.copytree('/etc/apache2', config_path)

    webroot_path = os.path.join(apache_root, 'www')
    os.mkdir(webroot_path)

    main_config_path = os.path.join(config_path, 'apache2.conf')
    with open(main_config_path, 'w') as file_h:
        file_h.write('''\
ServerRoot "{config}"
DefaultRuntimeDir ${{APACHE_RUN_DIR}}
PidFile ${{APACHE_PID_FILE}}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
User ${{APACHE_RUN_USER}}
Group ${{APACHE_RUN_GROUP}}
HostnameLookups Off
ErrorLog ${{APACHE_LOG_DIR}}/error.log
LogLevel warn

IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf

Include ports.conf

<Directory />
    Options FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

<Directory /usr/share>
    AllowOverride None
    Require all granted
</Directory>

<Directory {webroot}/>
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

AccessFileName .htaccess

<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{{Referer}}i\" \"%{{User-Agent}}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{{Referer}}i\" \"%{{User-Agent}}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{{Referer}}i -> %U" referer
LogFormat "%{{User-agent}}i" agent

IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf
'''.format(config=config_path, webroot=webroot_path))

    with open(os.path.join(config_path, 'ports.conf'), 'w') as file_h:
        file_h.write('''\
Listen {http}
<IfModule ssl_module>
    Listen {https}
</IfModule>
<IfModule mod_gnutls.c>
    Listen {https}
</IfModule>
'''.format(http=http_port, https=https_port))

    new_environ = os.environ.copy()
    new_environ['APACHE_CONFDIR'] = config_path

    run_path = os.path.join(config_path, 'run')
    lock_path = os.path.join(config_path, 'lock')
    logs_path = os.path.join(config_path, 'logs')
    os.mkdir(run_path)
    os.mkdir(lock_path)
    os.mkdir(logs_path)

    user = getpass.getuser()
    user = user if user != 'root' else 'www-data'
    group = user

    with open(os.path.join(config_path, 'envvars'), 'w') as file_h:
        file_h.write('''\
unset HOME
export APACHE_RUN_USER={user}
export APACHE_RUN_GROUP={group}
export APACHE_PID_FILE={run_path}/apache2.pid
export APACHE_RUN_DIR={run_path}
export APACHE_LOCK_DIR={lock_path}
export APACHE_LOG_DIR={logs_path}
export LANG=C
'''.format(user=user, group=group, run_path=run_path, lock_path=lock_path, logs_path=logs_path))

    new_environ['APACHE_RUN_USER'] = user
    new_environ['APACHE_RUN_GROUP'] = group
    new_environ['APACHE_PID_FILE'] = os.path.join(run_path, 'apache.pid')
    new_environ['APACHE_RUN_DIR'] = run_path
    new_environ['APACHE_LOCK_DIR'] = lock_path
    new_environ['APACHE_LOG_DIR'] = logs_path

    le_host = 'apache.{0}.wtf'.format(wtf_prefix)

    with open(os.path.join(config_path, 'sites-available', '000-default.conf'), 'w') as file_h:
        file_h.write('''\
<VirtualHost *:{http}>
    ServerAdmin webmaster@localhost
    ServerName {le_host}
    DocumentRoot {webroot}
    
    ErrorLog ${{APACHE_LOG_DIR}}/error.log
    CustomLog ${{APACHE_LOG_DIR}}/access.log combined
</VirtualHost>
'''.format(http=http_port, le_host=le_host, webroot=webroot_path))

    key_path = key_path if key_path \
        else pkg_resources.resource_filename('certbot_integration_tests', 'assets/key.pem')
    cert_path = cert_path if cert_path \
        else pkg_resources.resource_filename('certbot_integration_tests', 'assets/cert.pem')

    with open(os.path.join(config_path, 'sites-available', 'default-ssl.conf'), 'w') as file_h:
        file_h.write('''\
<IfModule mod_ssl.c>
    <VirtualHost _default_:{https}>
        ServerAdmin webmaster@localhost
        ServerName {le_host}
        DocumentRoot {webroot}
        
        ErrorLog ${{APACHE_LOG_DIR}}/error.log
        CustomLog ${{APACHE_LOG_DIR}}/access.log combined
        
        SSLEngine on
        SSLCertificateFile {cert_path}
        SSLCertificateKeyFile {key_path}
        
        <FilesMatch "\.(cgi|shtml|phtml|php)$">
            SSLOptions +StdEnvVars
        </FilesMatch>
        
        <Directory /usr/lib/cgi-bin>
            SSLOptions +StdEnvVars
        </Directory>
    </VirtualHost>
</IfModule>
'''.format(https=https_port, le_host=le_host, webroot=webroot_path,
           cert_path=cert_path, key_path=key_path))

    return new_environ


def test():
    env = construct_apache_config_dir('/tmp/test1', 5001, 5002)
    subprocess.call(['apache2', '-f', '/tmp/test1/config/apache2.conf'], env=env)
