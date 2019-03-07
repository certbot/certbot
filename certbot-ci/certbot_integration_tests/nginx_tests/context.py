import os
import subprocess
import random
import contextlib
import ssl

from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.utils import misc
from certbot_integration_tests.nginx_tests import nginx_config as config


class IntegrationTestsContext(certbot_context.IntegrationTestsContext):
    """General fixture describing a certbot-nginx integration tests context"""
    def __init__(self, request):
        super(IntegrationTestsContext, self).__init__(request)

        self.nginx_root = os.path.join(self.workspace, 'nginx')
        os.mkdir(self.nginx_root)

        self.webroot = os.path.join(self.nginx_root, 'webroot')
        os.mkdir(self.webroot)
        with open(os.path.join(self.webroot, 'index.html'), 'w') as file_handler:
            file_handler.write('Hello World!')

        self.other_port = random.randint(6000, 6999)

        self.key_path, self.cert_path = config.create_self_signed_certificate(self.nginx_root)

        self.nginx_config_path = os.path.join(self.nginx_root, 'nginx.conf')
        self.nginx_config = None

    @contextlib.contextmanager
    def nginx_server(self, default_server):
        self.nginx_config = config.construct_nginx_config(
            self.nginx_root, self.webroot, self.key_path, self.cert_path, self.http_01_port,
            self.tls_alpn_01_port, self.other_port, default_server, self.worker_id)
        with open(self.nginx_config_path, 'w') as file:
            file.write(self.nginx_config)

        process = subprocess.Popen(['nginx', '-c', self.nginx_config_path, '-g', 'daemon off;'])
        try:
            assert not process.poll()
            misc.check_until_timeout('http://localhost:{0}'.format(self.http_01_port))
            yield True
        finally:
            process.terminate()
            process.wait()

    def certbot_test_nginx(self, args):
        command = ['--authenticator', 'nginx', '--installer', 'nginx',
                   '--nginx-server-root', self.nginx_root]
        command.extend(args)
        return self._common_test(command)

    def assert_deployment_and_rollback(self, certname):
        server_cert = ssl.get_server_certificate(('localhost', self.tls_alpn_01_port))
        with open(os.path.join(self.workspace, 'conf/live/{0}/cert.pem'.format(certname)), 'r') as file:
            certbot_cert = file.read()

        assert server_cert == certbot_cert

        command = ['--authenticator', 'nginx', '--installer', 'nginx',
                   '--nginx-server-root', self.nginx_root,
                   'rollback', '--checkpoints', '1']
        self._common_test_no_force_renew(command)

        with open(self.nginx_config_path, 'r') as file_h:
            current_nginx_config = file_h.read()

        assert self.nginx_config == current_nginx_config
