"""Tests for letsencrypt.client.configuration."""
import unittest

import mock


class NamespaceConfigTest(unittest.TestCase):
    """Tests for letsencrypt.client.configuration.NamespaceConfig."""

    def setUp(self):
        from letsencrypt.client.configuration import NamespaceConfig
        namespace = mock.MagicMock(
            foo='bar', server='acme-server.org:443')
        self.config = NamespaceConfig(namespace)

    def test_proxy_getattr(self):
        self.assertEqual(self.config.foo, 'bar')

    @mock.patch('letsencrypt.client.configuration.constants')
    def test_dynamic_dirs(self, constants):
        constants.WORK_DIR='/tmp/foo'
        constants.CONFIG_DIR='/tmp/etc/foo'
        constants.TEMP_CHECKPOINT_DIR = 't'
        constants.IN_PROGRESS_DIR = '../p'
        constants.CERT_KEY_BACKUP_DIR = 'c/'
        constants.BACKUP_DIR = 'b'
        constants.KEY_DIR = 'k'
        constants.REC_TOKEN_DIR = '/r'
        self.assertEqual(self.config.work_dir, '/tmp/foo')
        self.assertEqual(self.config.config_dir, '/tmp/etc/foo')
        self.assertEqual(self.config.backup_dir, '/tmp/foo/b')
        self.assertEqual(self.config.key_dir, '/tmp/etc/foo/k')
        self.assertEqual(self.config.temp_checkpoint_dir, '/tmp/foo/t')
        self.assertEqual(self.config.in_progress_dir, '/tmp/foo/../p')
        self.assertEqual(
            self.config.cert_key_backup, '/tmp/foo/c/acme-server.org')
        self.assertEqual(self.config.rec_token_dir, '/r')


if __name__ == '__main__':
    unittest.main()
