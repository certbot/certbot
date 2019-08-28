import errno
import os
import signal
import subprocess

from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.apache_tests import apache_config
from certbot_integration_tests.utils import certbot_call


class IntegrationTestsContext(certbot_context.IntegrationTestsContext):
    def __init__(self, request):
        super(IntegrationTestsContext, self).__init__(request)

        subprocess.check_output(['chmod', '+x', self.workspace])

        self.apache_root = os.path.join(self.workspace, 'apache')
        os.mkdir(self.apache_root)

        self.env, self.config_dir, self.pid_file = apache_config.construct_apache_config_dir(
            self.apache_root, self.http_01_port, self.tls_alpn_01_port,
            wtf_prefix=self.worker_id)

    def cleanup(self):
        self._stop_apache()
        super(IntegrationTestsContext, self).cleanup()

    def certbot_test_apache(self, args):
        command = ['--authenticator', 'apache', '--installer', 'apache',
                   '--apache-server-root', self.config_dir,
                   '--apache-challenge-location', self.apache_root]
        command.extend(args)

        return certbot_call.certbot_test(
            command, self.directory_url, self.http_01_port, self.tls_alpn_01_port,
            self.config_dir, self.workspace, env=self.env, force_renew=True)

    def _stop_apache(self):
        try:
            with open(self.pid_file) as file_h:
                pid = int(file_h.read().strip())
        except BaseException:
            pid = None

        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError as err:
                # Ignore "No such process" error, Apache may already be stopped.
                if err.errno != errno.ESRCH:
                    raise
