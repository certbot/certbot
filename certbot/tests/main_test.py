"""Tests for certbot.main."""
import os
import shutil
import tempfile
import unittest

import mock
import six

from certbot import cli
from certbot import configuration
from certbot import errors
from certbot import main
from certbot.plugins import disco as plugins_disco


class MainTest(unittest.TestCase):
    """Tests for certbot.main"""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.tmp_dir, 'config')
        self.work_dir = os.path.join(self.tmp_dir, 'work')
        self.logs_dir = os.path.join(self.tmp_dir, 'logs')
        self.standard_args = ['--config-dir', self.config_dir,
                              '--work-dir', self.work_dir,
                              '--logs-dir', self.logs_dir, '--text']

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def _call(self, args, stdout=None):
        "Run the client with output streams mocked out"
        args = self.standard_args + args

        toy_stdout = stdout if stdout else six.StringIO()
        with mock.patch('certbot.main.sys.stdout', new=toy_stdout):
            with mock.patch('certbot.main.sys.stderr') as stderr:
                ret = main.main(args[:])  # NOTE: parser can alter its args!
        return ret, toy_stdout, stderr

    def test_args_conflict(self):
        args = ['renew', '--dialog', '--text']
        self.assertRaises(errors.Error, self._call, args)


class ObtainCertTest(unittest.TestCase):
    """Tests for certbot.main.obtain_cert."""

    def setUp(self):
        self.get_utility_patch = mock.patch(
            'certbot.main.zope.component.getUtility')
        self.mock_get_utility = self.get_utility_patch.start()

    def tearDown(self):
        self.get_utility_patch.stop()

    def _call(self, args):
        plugins = plugins_disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        with mock.patch('certbot.main._init_le_client') as mock_init:
            main.obtain_cert(config, plugins)

        return mock_init()  # returns the client

    @mock.patch('certbot.main._auth_from_domains')
    def test_no_reinstall_text_pause(self, mock_auth):
        mock_notification = self.mock_get_utility().notification
        mock_notification.side_effect = self._assert_no_pause
        mock_auth.return_value = (mock.ANY, 'reinstall')
        self._call('certonly --webroot -d example.com -t'.split())

    def _assert_no_pause(self, message, height=42, pause=True):
        # pylint: disable=unused-argument
        self.assertFalse(pause)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
