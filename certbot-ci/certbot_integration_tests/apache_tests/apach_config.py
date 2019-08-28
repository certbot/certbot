import shutil
import os

import pkg_resources


def construct_apache_config_dir(apache_root, http_port, https_port, key_path=None,
                                cert_path=None, wtf_prefix='le'):
    config_path = os.path.join(apache_root, 'config')
    shutil.copytree('/etc/apache2', config_path)

    webroot_path = os.path.join(apache_root, 'www')
    os.mkdir(webroot_path)

    main_config_path = os.path.join(config_path, 'apache2.conf')
    with open(main_config_path, 'r') as file_h:
        data = file_h.read()
    data.replace('/var/www/html', webroot_path)
    with open(main_config_path, 'w') as file_h:
        file_h.write(data)

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

    with open(os.path.join(config_path, 'envvars'), 'w') as file_h:
        file_h.write('''\
unset HOME
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
export APACHE_PID_FILE={run_path}/apache2.pid
export APACHE_RUN_DIR={run_path}
export APACHE_LOCK_DIR={lock_path}
export APACHE_LOG_DIR={logs_path}
export LANG=C
'''.format(run_path=run_path, lock_path=lock_path, logs_path=logs_path))

    le_host = 'apache.{0}.wtf'.format(wtf_prefix)

    with open(os.path.join(config_path, 'sites-available', '0000-default.conf')) as file_h:
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
