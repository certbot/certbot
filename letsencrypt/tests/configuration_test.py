"""Tests for letsencrypt.configuration."""
import os
import unittest

import mock


class NamespaceConfigTest(unittest.TestCase):
    """Tests for letsencrypt.configuration.NamespaceConfig."""

    def setUp(self):
        from letsencrypt.configuration import NamespaceConfig
        self.namespace = mock.MagicMock(
            config_dir='/tmp/config', work_dir='/tmp/foo', foo='bar',
            server='https://acme-server.org:443/new')
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
        constants.CERT_DIR = 'certs'
        constants.IN_PROGRESS_DIR = '../p'
        constants.KEY_DIR = 'keys'
        constants.REC_TOKEN_DIR = '/r'
        constants.RENEWER_CONFIG_FILENAME = 'r.conf'
        constants.TEMP_CHECKPOINT_DIR = 't'

        self.assertEqual(
            self.config.accounts_dir, '/tmp/config/acc/acme-server.org:443/new')
        self.assertEqual(
            self.config.account_keys_dir,
            '/tmp/config/acc/acme-server.org:443/new/keys')
        self.assertEqual(self.config.backup_dir, '/tmp/foo/backups')
        self.assertEqual(self.config.cert_dir, '/tmp/config/certs')
        self.assertEqual(
            self.config.cert_key_backup, '/tmp/foo/c/acme-server.org:443/new')
        self.assertEqual(self.config.in_progress_dir, '/tmp/foo/../p')
        self.assertEqual(self.config.key_dir, '/tmp/config/keys')
        self.assertEqual(self.config.rec_token_dir, '/r')
        self.assertEqual(self.config.renewer_config_file, '/tmp/config/r.conf')
        self.assertEqual(self.config.temp_checkpoint_dir, '/tmp/foo/t')


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
