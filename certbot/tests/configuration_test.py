"""Tests for certbot.configuration."""
import os
import unittest

import mock

from certbot import errors

from certbot.tests import util as test_util

class NamespaceConfigTest(test_util.ConfigTestCase):
    """Tests for certbot.configuration.NamespaceConfig."""

    def setUp(self):
        super(NamespaceConfigTest, self).setUp()
        self.config.foo = 'bar'
        self.config.server = 'https://acme-server.org:443/new'
        self.config.tls_sni_01_port = 1234
        self.config.http01_port = 4321

    def test_init_same_ports(self):
        self.config.namespace.tls_sni_01_port = 4321
        from certbot.configuration import NamespaceConfig
        self.assertRaises(errors.Error, NamespaceConfig, self.config.namespace)

    def test_proxy_getattr(self):
        self.assertEqual(self.config.foo, 'bar')
        self.assertEqual(self.config.work_dir, os.path.join(self.tempdir, 'work'))

    def test_server_path(self):
        self.assertEqual(['acme-server.org:443', 'new'],
                         self.config.server_path.split(os.path.sep))

        self.config.namespace.server = ('http://user:pass@acme.server:443'
                                 '/p/a/t/h;parameters?query#fragment')
        self.assertEqual(['user:pass@acme.server:443', 'p', 'a', 't', 'h'],
                         self.config.server_path.split(os.path.sep))

    @mock.patch('certbot.configuration.constants')
    def test_dynamic_dirs(self, constants):
        constants.ACCOUNTS_DIR = 'acc'
        constants.BACKUP_DIR = 'backups'
        constants.CSR_DIR = 'csr'

        constants.IN_PROGRESS_DIR = '../p'
        constants.KEY_DIR = 'keys'
        constants.TEMP_CHECKPOINT_DIR = 't'

        self.assertEqual(
            self.config.accounts_dir, os.path.join(
                self.config.config_dir, 'acc/acme-server.org:443/new'))
        self.assertEqual(
                self.config.backup_dir, os.path.join(self.config.work_dir, 'backups'))
        self.assertEqual(
                self.config.csr_dir, os.path.join(self.config.config_dir, 'csr'))
        self.assertEqual(
                self.config.in_progress_dir, os.path.join(self.config.work_dir, '../p'))
        self.assertEqual(
                self.config.key_dir, os.path.join(self.config.config_dir, 'keys'))
        self.assertEqual(
                self.config.temp_checkpoint_dir, os.path.join(self.config.work_dir, 't'))

    def test_absolute_paths(self):
        from certbot.configuration import NamespaceConfig

        config_base = "foo"
        work_base = "bar"
        logs_base = "baz"
        server = "mock.server"

        mock_namespace = mock.MagicMock(spec=['config_dir', 'work_dir',
                                              'logs_dir', 'http01_port',
                                              'tls_sni_01_port',
                                              'domains', 'server'])
        mock_namespace.config_dir = config_base
        mock_namespace.work_dir = work_base
        mock_namespace.logs_dir = logs_base
        mock_namespace.server = server
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

    @mock.patch('certbot.configuration.constants')
    def test_renewal_dynamic_dirs(self, constants):
        constants.ARCHIVE_DIR = 'a'
        constants.LIVE_DIR = 'l'
        constants.RENEWAL_CONFIGS_DIR = 'renewal_configs'

        self.assertEqual(
                self.config.default_archive_dir, os.path.join(self.config.config_dir, 'a'))
        self.assertEqual(
                self.config.live_dir, os.path.join(self.config.config_dir, 'l'))
        self.assertEqual(
                self.config.renewal_configs_dir, os.path.join(
                    self.config.config_dir, 'renewal_configs'))

    def test_renewal_absolute_paths(self):
        from certbot.configuration import NamespaceConfig

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

        self.assertTrue(os.path.isabs(config.default_archive_dir))
        self.assertTrue(os.path.isabs(config.live_dir))
        self.assertTrue(os.path.isabs(config.renewal_configs_dir))

    def test_get_and_set_attr(self):
        self.config.foo = 42
        self.assertEqual(self.config.namespace.foo, 42)
        self.config.namespace.bar = 1337
        self.assertEqual(self.config.bar, 1337)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
