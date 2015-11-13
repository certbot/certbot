"""Tests for letsencrypt.configuration."""
import os
import unittest

import mock

from letsencrypt import errors


class NamespaceConfigTest(unittest.TestCase):
    """Tests for letsencrypt.configuration.NamespaceConfig."""

    def setUp(self):
        self.namespace = mock.MagicMock(
            config_dir='/tmp/config', work_dir='/tmp/foo', foo='bar',
            server='https://acme-server.org:443/new',
            tls_sni_01_port=1234, http01_port=4321)
        from letsencrypt.configuration import NamespaceConfig
        self.config = NamespaceConfig(self.namespace)

    def test_init_same_ports(self):
        self.namespace.tls_sni_01_port = 4321
        from letsencrypt.configuration import NamespaceConfig
        self.assertRaises(errors.Error, NamespaceConfig, self.namespace)

    def test_proxy_getattr(self):
        self.assertEqual(self.config.foo, 'bar')
        self.assertEqual(self.config.work_dir, '/tmp/foo')

    def test_server_path(self):
        self.assertEqual(['acme-server.org:443', 'new'],
                         self.config.server_path.split(os.path.sep))

        self.namespace.server = ('http://user:pass@acme.server:443'
                                 '/p/a/t/h;parameters?query#fragment')
        self.assertEqual(['user:pass@acme.server:443', 'p', 'a', 't', 'h'],
                         self.config.server_path.split(os.path.sep))

    @mock.patch('letsencrypt.configuration.constants')
    def test_dynamic_dirs(self, constants):
        constants.ACCOUNTS_DIR = 'acc'
        constants.BACKUP_DIR = 'backups'
        constants.CSR_DIR = 'csr'

        constants.IN_PROGRESS_DIR = '../p'
        constants.KEY_DIR = 'keys'
        constants.TEMP_CHECKPOINT_DIR = 't'

        self.assertEqual(
            self.config.accounts_dir, '/tmp/config/acc/acme-server.org:443/new')
        self.assertEqual(self.config.backup_dir, '/tmp/foo/backups')
        self.assertEqual(self.config.csr_dir, '/tmp/config/csr')
        self.assertEqual(self.config.in_progress_dir, '/tmp/foo/../p')
        self.assertEqual(self.config.key_dir, '/tmp/config/keys')
        self.assertEqual(self.config.temp_checkpoint_dir, '/tmp/foo/t')

    def test_http01_port(self):
        self.assertEqual(4321, self.config.http01_port)
        self.namespace.http01_port = None
        self.assertEqual(80, self.config.http01_port)

    def test_absolute_paths(self):
        from letsencrypt.configuration import NamespaceConfig

        config_base = "foo"
        work_base = "bar"
        logs_base = "baz"

        mock_namespace = mock.MagicMock(spec=['config_dir', 'work_dir',
                                              'logs_dir', 'http01_port',
                                              'tls_sni_01_port',
                                              'domains', 'server'])
        mock_namespace.config_dir = config_base
        mock_namespace.work_dir = work_base
        mock_namespace.logs_dir = logs_base
        config = NamespaceConfig(mock_namespace)

        self.assertTrue(os.path.isabs(config.config_dir))
        self.assertEqual(config.config_dir,
                         os.path.join(os.getcwd(), config_base))
        self.assertTrue(os.path.isabs(config.work_dir))
        self.assertEqual(config.work_dir,
                         os.path.join(os.getcwd(), work_base))
        self.assertTrue(os.path.isabs(config.logs_dir))
        self.assertEqual(config.logs_dir,
                         os.path.join(os.getcwd(), logs_base))
        self.assertTrue(os.path.isabs(config.accounts_dir))
        self.assertTrue(os.path.isabs(config.backup_dir))
        self.assertTrue(os.path.isabs(config.csr_dir))
        self.assertTrue(os.path.isabs(config.in_progress_dir))
        self.assertTrue(os.path.isabs(config.key_dir))
        self.assertTrue(os.path.isabs(config.temp_checkpoint_dir))


class RenewerConfigurationTest(unittest.TestCase):
    """Test for letsencrypt.configuration.RenewerConfiguration."""

    def setUp(self):
        self.namespace = mock.MagicMock(config_dir='/tmp/config')
        from letsencrypt.configuration import RenewerConfiguration
        self.config = RenewerConfiguration(self.namespace)

    @mock.patch('letsencrypt.configuration.constants')
    def test_dynamic_dirs(self, constants):
        constants.ARCHIVE_DIR = 'a'
        constants.LIVE_DIR = 'l'
        constants.RENEWAL_CONFIGS_DIR = 'renewal_configs'
        constants.RENEWER_CONFIG_FILENAME = 'r.conf'

        self.assertEqual(self.config.archive_dir, '/tmp/config/a')
        self.assertEqual(self.config.live_dir, '/tmp/config/l')
        self.assertEqual(
            self.config.renewal_configs_dir, '/tmp/config/renewal_configs')
        self.assertEqual(self.config.renewer_config_file, '/tmp/config/r.conf')

    def test_absolute_paths(self):
        from letsencrypt.configuration import NamespaceConfig
        from letsencrypt.configuration import RenewerConfiguration

        config_base = "foo"
        work_base = "bar"
        logs_base = "baz"

        mock_namespace = mock.MagicMock(spec=['config_dir', 'work_dir',
                                              'logs_dir', 'http01_port',
                                              'tls_sni_01_port',
                                              'domains', 'server'])
        mock_namespace.config_dir = config_base
        mock_namespace.work_dir = work_base
        mock_namespace.logs_dir = logs_base
        config = RenewerConfiguration(NamespaceConfig(mock_namespace))

        self.assertTrue(os.path.isabs(config.archive_dir))
        self.assertTrue(os.path.isabs(config.live_dir))
        self.assertTrue(os.path.isabs(config.renewal_configs_dir))
        self.assertTrue(os.path.isabs(config.renewer_config_file))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
