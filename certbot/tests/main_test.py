"""Tests for certbot.main."""
import unittest


import mock


from certbot import cli
from certbot import configuration
from certbot.plugins import disco as plugins_disco


class ObtainCertTest(unittest.TestCase):
    """Tests for certbot.main.obtain_cert."""

    def _call(self, args):
        plugins = plugins_disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        from certbot import main
        with mock.patch('certbot.main._init_le_client') as mock_init:
            main.obtain_cert(config, plugins)

        return mock_init()  # returns the client

    @mock.patch('certbot.main._auth_from_domains')
    def test_no_reinstall_text_pause(self, mock_auth):
        mock_auth.return_value = (mock.ANY, 'reinstall')
        # This hangs if the reinstallation notification pauses
        self._call('certonly --webroot -d example.com -t'.split())


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
