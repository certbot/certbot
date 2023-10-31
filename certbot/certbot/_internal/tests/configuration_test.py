"""Tests for certbot.configuration."""
import sys
import unittest
from unittest import mock
import warnings

import pytest

from certbot import errors
from certbot._internal import cli
from certbot._internal import constants
from certbot._internal.plugins import disco
from certbot.compat import misc
from certbot.compat import os
from certbot.tests import util as test_util


class NamespaceConfigTest(test_util.ConfigTestCase):
    """Tests for certbot.configuration.NamespaceConfig."""

    def setUp(self):
        super().setUp()
        self.config.foo = 'bar' # pylint: disable=blacklisted-name
        self.config.server = 'https://acme-server.org:443/new'
        self.config.https_port = 1234
        self.config.http01_port = 4321

    def test_init_same_ports(self):
        self.config.https_port = 4321
        from certbot.configuration import NamespaceConfig
        with pytest.raises(errors.Error):
            NamespaceConfig(self.config.namespace)

    def test_proxy_getattr(self):
        assert self.config.foo == 'bar'
        assert self.config.work_dir == os.path.join(self.tempdir, 'work')

    def test_server_path(self):
        assert ['acme-server.org:443', 'new'] == \
                         self.config.server_path.split(os.path.sep)

        self.config.server = ('http://user:pass@acme.server:443'
                                 '/p/a/t/h;parameters?query#fragment')
        assert ['user:pass@acme.server:443', 'p', 'a', 't', 'h'] == \
                         self.config.server_path.split(os.path.sep)

    @mock.patch('certbot.configuration.constants')
    def test_dynamic_dirs(self, mock_constants):
        mock_constants.ACCOUNTS_DIR = 'acc'
        mock_constants.BACKUP_DIR = 'backups'
        mock_constants.CSR_DIR = 'csr'

        mock_constants.IN_PROGRESS_DIR = '../p'
        mock_constants.KEY_DIR = 'keys'
        mock_constants.TEMP_CHECKPOINT_DIR = 't'

        ref_path = misc.underscores_for_unsupported_characters_in_path(
            'acc/acme-server.org:443/new')
        assert os.path.normpath(self.config.accounts_dir) == \
            os.path.normpath(os.path.join(self.config.config_dir, ref_path))
        assert os.path.normpath(self.config.backup_dir) == \
            os.path.normpath(os.path.join(self.config.work_dir, 'backups'))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            assert os.path.normpath(self.config.csr_dir) == \
                os.path.normpath(os.path.join(self.config.config_dir, 'csr'))
            assert os.path.normpath(self.config.key_dir) == \
                os.path.normpath(os.path.join(self.config.config_dir, 'keys'))
        assert os.path.normpath(self.config.in_progress_dir) == \
            os.path.normpath(os.path.join(self.config.work_dir, '../p'))
        assert os.path.normpath(self.config.temp_checkpoint_dir) == \
            os.path.normpath(os.path.join(self.config.work_dir, 't'))

    def test_absolute_paths(self):
        from certbot.configuration import NamespaceConfig

        config_base = "foo"
        work_base = "bar"
        logs_base = "baz"
        server = "mock.server"

        mock_namespace = mock.MagicMock(spec=['config_dir', 'work_dir',
                                              'logs_dir', 'http01_port',
                                              'https_port',
                                              'domains', 'server'])
        mock_namespace.config_dir = config_base
        mock_namespace.work_dir = work_base
        mock_namespace.logs_dir = logs_base
        mock_namespace.server = server
        config = NamespaceConfig(mock_namespace)

        assert os.path.isabs(config.config_dir)
        assert config.config_dir == \
                         os.path.join(os.getcwd(), config_base)
        assert os.path.isabs(config.work_dir)
        assert config.work_dir == \
                         os.path.join(os.getcwd(), work_base)
        assert os.path.isabs(config.logs_dir)
        assert config.logs_dir == \
                         os.path.join(os.getcwd(), logs_base)
        assert os.path.isabs(config.accounts_dir)
        assert os.path.isabs(config.backup_dir)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            assert os.path.isabs(config.csr_dir)
            assert os.path.isabs(config.key_dir)
        assert os.path.isabs(config.in_progress_dir)
        assert os.path.isabs(config.temp_checkpoint_dir)

    @mock.patch('certbot.configuration.constants')
    def test_renewal_dynamic_dirs(self, mock_constants):
        mock_constants.ARCHIVE_DIR = 'a'
        mock_constants.LIVE_DIR = 'l'
        mock_constants.RENEWAL_CONFIGS_DIR = 'renewal_configs'

        assert self.config.default_archive_dir == os.path.join(self.config.config_dir, 'a')
        assert self.config.live_dir == os.path.join(self.config.config_dir, 'l')
        assert self.config.renewal_configs_dir == os.path.join(
                    self.config.config_dir, 'renewal_configs')

    def test_renewal_absolute_paths(self):
        from certbot.configuration import NamespaceConfig

        config_base = "foo"
        work_base = "bar"
        logs_base = "baz"

        mock_namespace = mock.MagicMock(spec=['config_dir', 'work_dir',
                                              'logs_dir', 'http01_port',
                                              'https_port',
                                              'domains', 'server'])
        mock_namespace.config_dir = config_base
        mock_namespace.work_dir = work_base
        mock_namespace.logs_dir = logs_base
        config = NamespaceConfig(mock_namespace)

        assert os.path.isabs(config.default_archive_dir)
        assert os.path.isabs(config.live_dir)
        assert os.path.isabs(config.renewal_configs_dir)

    def test_get_and_set_attr(self):
        self.config.foo = 42
        assert self.config.namespace.foo == 42
        self.config.namespace.bar = 1337
        assert self.config.bar == 1337

    def test_hook_directories(self):
        assert self.config.renewal_hooks_dir == \
                         os.path.join(self.config.config_dir,
                                      constants.RENEWAL_HOOKS_DIR)
        assert self.config.renewal_pre_hooks_dir == \
                         os.path.join(self.config.renewal_hooks_dir,
                                      constants.RENEWAL_PRE_HOOKS_DIR)
        assert self.config.renewal_deploy_hooks_dir == \
                         os.path.join(self.config.renewal_hooks_dir,
                                      constants.RENEWAL_DEPLOY_HOOKS_DIR)
        assert self.config.renewal_post_hooks_dir == \
                         os.path.join(self.config.renewal_hooks_dir,
                                      constants.RENEWAL_POST_HOOKS_DIR)

    def test_set_by_user_runtime_overrides(self):
        assert not self.config.set_by_user('something')
        self.config.something = 'a value'
        assert self.config.set_by_user('something')

    def test_set_by_user_exception(self):
        from certbot.configuration import NamespaceConfig

        # a newly created NamespaceConfig has no argument sources dict, so an
        # exception is raised
        config = NamespaceConfig(self.config.namespace)
        with pytest.raises(RuntimeError):
            config.set_by_user('whatever')

        # now set an argument sources dict
        config.set_argument_sources({})
        assert not config.set_by_user('whatever')

    def test_set_by_user_mutables(self):
        assert not self.config.set_by_user('domains')
        self.config.domains.append('example.org')
        assert self.config.set_by_user('domains')


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
