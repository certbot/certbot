"""Tests for letsencrypt.client.configuration."""
import os
import unittest

import mock


class NamespaceConfigTest(unittest.TestCase):
    """Tests for letsencrypt.client.configuration.NamespaceConfig."""

    def setUp(self):
        from letsencrypt.client.configuration import NamespaceConfig
        namespace = mock.MagicMock(
            config_dir='/tmp/config', work_dir='/tmp/foo', foo='bar',
            server='acme-server.org:443/new')
        self.config = NamespaceConfig(namespace)

    def test_proxy_getattr(self):
        self.assertEqual(self.config.foo, 'bar')
        self.assertEqual(self.config.work_dir, '/tmp/foo')

    def test_server_path(self):
        self.assertEqual(['acme-server.org:443', 'new'],
                         self.config.server_path.split(os.path.sep))

    def test_server_url(self):
        self.assertEqual(
            self.config.server_url, 'https://acme-server.org:443/new')

    @mock.patch('letsencrypt.client.configuration.constants')
    def test_dynamic_dirs(self, constants):
        constants.TEMP_CHECKPOINT_DIR = 't'
        constants.IN_PROGRESS_DIR = '../p'
        constants.CERT_KEY_BACKUP_DIR = 'c/'
        constants.REC_TOKEN_DIR = '/r'
        constants.ACCOUNTS_DIR = 'acc'
        constants.ACCOUNT_KEYS_DIR = 'keys'

        self.assertEqual(self.config.temp_checkpoint_dir, '/tmp/foo/t')
        self.assertEqual(self.config.in_progress_dir, '/tmp/foo/../p')
        self.assertEqual(
            self.config.cert_key_backup, '/tmp/foo/c/acme-server.org:443/new')
        self.assertEqual(self.config.rec_token_dir, '/r')
        self.assertEqual(
            self.config.accounts_dir, '/tmp/config/acc/acme-server.org:443/new')
        self.assertEqual(
            self.config.account_keys_dir,
            '/tmp/config/acc/acme-server.org:443/new/keys')


if __name__ == '__main__':
    unittest.main()
