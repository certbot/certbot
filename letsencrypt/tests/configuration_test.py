"""Tests for letsencrypt.configuration."""
import os
import unittest

import mock


class NamespaceConfigTest(unittest.TestCase):
    """Tests for letsencrypt.configuration.NamespaceConfig."""

    def setUp(self):
        self.namespace = mock.MagicMock(
            config_dir='/tmp/config', work_dir='/tmp/foo', foo='bar',
            server='https://acme-server.org:443/new')
        from letsencrypt.configuration import NamespaceConfig
        self.config = NamespaceConfig(self.namespace)

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
        constants.ACCOUNT_KEYS_DIR = 'keys'
        constants.BACKUP_DIR = 'backups'
        constants.CERT_KEY_BACKUP_DIR = 'c/'
        constants.CSR_DIR = 'csrs'
        constants.IN_PROGRESS_DIR = '../p'
        constants.KEY_DIR = 'keys'
        constants.REC_TOKEN_DIR = '/r'
        constants.TEMP_CHECKPOINT_DIR = 't'

        self.assertEqual(
            self.config.accounts_dir, '/tmp/config/acc/acme-server.org:443/new')
        self.assertEqual(
            self.config.account_keys_dir,
            '/tmp/config/acc/acme-server.org:443/new/keys')
        self.assertEqual(self.config.backup_dir, '/tmp/foo/backups')
        self.assertEqual(self.config.csr_dir, '/tmp/config/csrs')
        self.assertEqual(
            self.config.cert_key_backup, '/tmp/foo/c/acme-server.org:443/new')
        self.assertEqual(self.config.in_progress_dir, '/tmp/foo/../p')
        self.assertEqual(self.config.key_dir, '/tmp/config/keys')
        self.assertEqual(self.config.rec_token_dir, '/r')
        self.assertEqual(self.config.temp_checkpoint_dir, '/tmp/foo/t')


class RenewerConfigurationTest(unittest.TestCase):
    """Test for letsencrypt.configuration.RenewerConfiguration."""

    def setUp(self):
        self.namespace = mock.MagicMock(config_dir='/tmp/config')
        from letsencrypt.configuration import RenewerConfiguration
        self.config = RenewerConfiguration(self.namespace)

    @mock.patch('letsencrypt.configuration.constants')
    def test_dynamic_dirs(self, constants):
        constants.ARCHIVE_DIR = "a"
        constants.LIVE_DIR = 'l'
        constants.RENEWAL_CONFIGS_DIR = "renewal_configs"
        constants.RENEWER_CONFIG_FILENAME = 'r.conf'

        self.assertEqual(self.config.archive_dir, '/tmp/config/a')
        self.assertEqual(self.config.live_dir, '/tmp/config/l')
        self.assertEqual(
            self.config.renewal_configs_dir, '/tmp/config/renewal_configs')
        self.assertEqual(self.config.renewer_config_file, '/tmp/config/r.conf')


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
