"""Module to handle the context of nginx integration tests."""
import os
import subprocess
from collections.abc import Iterable


import pytest

from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.nginx_tests import nginx_config as config
from certbot_integration_tests.utils import certbot_call
from certbot_integration_tests.utils import constants
from certbot_integration_tests.utils import misc


class IntegrationTestsContext(certbot_context.IntegrationTestsContext):
    """General fixture describing a certbot-nginx integration tests context"""
    def __init__(self, request: pytest.FixtureRequest) -> None:
        super().__init__(request)

        self.nginx_root = os.path.join(self.workspace, 'nginx')
        os.mkdir(self.nginx_root)

        self.webroot = os.path.join(self.nginx_root, 'webroot')
        os.mkdir(self.webroot)
        with open(os.path.join(self.webroot, 'index.html'), 'w') as file_handler:
            file_handler.write('Hello World!')

        self.nginx_config_path = os.path.join(self.nginx_root, 'nginx.conf')
        self.nginx_config: str

        default_server = request.param['default_server']
        self.process = self._start_nginx(default_server)

    def cleanup(self) -> None:
        self._stop_nginx()
        super().cleanup()

    def certbot_test_nginx(self, args: Iterable[str]) -> tuple[str, str]:
        """
        Main command to execute certbot using the nginx plugin.
        :param list args: list of arguments to pass to nginx
        :param bool force_renew: set to False to not renew by default
        """
        command = ['--authenticator', 'nginx', '--installer', 'nginx',
                   '--nginx-server-root', self.nginx_root]
        command.extend(args)
        return certbot_call.certbot_test(
            command, self.directory_url, self.http_01_port, self.tls_alpn_01_port,
            self.config_dir, self.workspace, force_renew=True)

    def _start_nginx(self, default_server: bool) -> subprocess.Popen[bytes]:
        self.nginx_config = config.construct_nginx_config(
            self.nginx_root, self.webroot, self.http_01_port, self.tls_alpn_01_port,
            self.other_port, default_server, wtf_prefix=self.worker_id)
        with open(self.nginx_config_path, 'w') as file:
            file.write(self.nginx_config)

        # pylint: disable=consider-using-with
        process = subprocess.Popen(['nginx', '-c', self.nginx_config_path, '-g', 'daemon off;'])

        assert process.poll() is None
        misc.check_until_timeout('http://localhost:{0}'.format(self.http_01_port))
        return process

    def _stop_nginx(self) -> None:
        assert self.process.poll() is None
        self.process.terminate()
        self.process.wait(constants.MAX_SUBPROCESS_WAIT)
