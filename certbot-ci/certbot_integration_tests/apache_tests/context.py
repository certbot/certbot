import os

from certbot_integration_tests.certbot_tests import context as certbot_context


class IntegrationTestsContext(certbot_context.IntegrationTestsContext):
    def __init__(self, request):
        super(IntegrationTestsContext, self).__init__(request)

        self.apache_root = os.path.join(self.workspace, 'apache')
        os.mkdir(self.apache_root)

        self.webroot = os.path.join(self.apache_root, 'www')
        os.mkdir(self.webroot)
        with open(os.path.join(self.webroot, 'index.html'), 'w') as file_handler:
            file_handler.write('Hello World!')

        self.process = self._start_apache()

    def cleanup(self):
        self._stop_apache()
        super(IntegrationTestsContext, self).cleanup()

    def _start_apache(self):
        pass

    def _stop_apache(self):
        pass
