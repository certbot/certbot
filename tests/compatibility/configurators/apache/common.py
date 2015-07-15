"""Provides a common base for Apache tests"""
import mock

from tests.compatibilty import configurators

class ApacheConfiguratorCommonTester(configurators.common.ConfiguratorTester):
    """A common base for Apache test configurators"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        super(ApacheConfiguratorCommonTester, self).__init__(args)
        self._patch = mock.patch('letsencrypt_apache.configurator.subprocess')
        self._mock = self._patch.start()
        self._mock.check_call = self._check_call
        self._apache_configurator = None

    def __getattr__(self, name):
        """Wraps the Apache Configurator methods"""
        method = getattr(self._apache_configurator, name, None)
        if callable(method):
            return method
        else:
            raise AttributeError()

    def _check_call(self, command, *args, **kwargs):
        """A function to mock the call to subprocess.check_call"""

    def load_config(self):
        """Loads the next configuration for the plugin to test"""
        raise NotImplementedError()

    def get_test_domain_names(self):
        """Returns a list of domain names to test against the plugin"""
        raise NotImplementedError()
