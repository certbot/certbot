"""Tests for certbot.main."""
import os
import shutil
import tempfile
import unittest

import mock

from certbot import cli
from certbot import colored_logging
from certbot import constants
from certbot import configuration
from certbot import errors
from certbot import log
from certbot.plugins import disco as plugins_disco

class MainTest(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass

    def test_handle_identical_cert_request_pending(self):
        from certbot import main
        mock_lineage = mock.Mock()
        mock_lineage.ensure_deployed.return_value = False
        # pylint: disable=protected-access
        ret = main._handle_identical_cert_request(mock.Mock(), mock_lineage)
        self.assertEqual(ret, ("reinstall", mock_lineage))

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

        from certbot import main
        with mock.patch('certbot.main._init_le_client') as mock_init:
            main.obtain_cert(config, plugins)

        return mock_init()  # returns the client

    @mock.patch('certbot.main._auth_from_domains')
    def test_no_reinstall_text_pause(self, mock_auth):
        mock_notification = self.mock_get_utility().notification
        mock_notification.side_effect = self._assert_no_pause
        mock_auth.return_value = ('reinstall', mock.ANY)
        self._call('certonly --webroot -d example.com -t'.split())

    def _assert_no_pause(self, message, height=42, pause=True):
        # pylint: disable=unused-argument
        self.assertFalse(pause)


class SetupLogFileHandlerTest(unittest.TestCase):
    """Tests for certbot.main.setup_log_file_handler."""

    def setUp(self):
        self.config = mock.Mock(spec_set=['logs_dir'],
                                logs_dir=tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.config.logs_dir)

    def _call(self, *args, **kwargs):
        from certbot.main import setup_log_file_handler
        return setup_log_file_handler(*args, **kwargs)

    @mock.patch('certbot.main.logging.handlers.RotatingFileHandler')
    def test_ioerror(self, mock_handler):
        mock_handler.side_effect = IOError
        self.assertRaises(errors.Error, self._call,
                          self.config, "test.log", "%s")


class SetupLoggingTest(unittest.TestCase):
    """Tests for certbot.main.setup_logging."""

    def setUp(self):
        self.config = mock.Mock(
            logs_dir=tempfile.mkdtemp(),
            noninteractive_mode=False, quiet=False, text_mode=False,
            verbose_count=constants.CLI_DEFAULTS['verbose_count'])

    def tearDown(self):
        shutil.rmtree(self.config.logs_dir)

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.main import setup_logging
        return setup_logging(*args, **kwargs)

    @mock.patch('certbot.main.logging.getLogger')
    def test_defaults(self, mock_get_logger):
        self._call(self.config)

        cli_handler = mock_get_logger().addHandler.call_args_list[0][0][0]
        self.assertEqual(cli_handler.level, -self.config.verbose_count * 10)
        self.assertTrue(
            isinstance(cli_handler, log.DialogHandler))

    @mock.patch('certbot.main.logging.getLogger')
    def test_quiet_mode(self, mock_get_logger):
        self.config.quiet = self.config.noninteractive_mode = True
        self._call(self.config)

        cli_handler = mock_get_logger().addHandler.call_args_list[0][0][0]
        self.assertEqual(cli_handler.level, constants.QUIET_LOGGING_LEVEL)
        self.assertTrue(
            isinstance(cli_handler, colored_logging.StreamHandler))


class MakeOrVerifyCoreDirTest(unittest.TestCase):
    """Tests for certbot.main.make_or_verify_core_dir."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def _call(self, *args, **kwargs):
        from certbot.main import make_or_verify_core_dir
        return make_or_verify_core_dir(*args, **kwargs)

    def test_success(self):
        new_dir = os.path.join(self.dir, 'new')
        self._call(new_dir, 0o700, os.geteuid(), False)
        self.assertTrue(os.path.exists(new_dir))

    @mock.patch('certbot.main.util.make_or_verify_dir')
    def test_failure(self, mock_make_or_verify):
        mock_make_or_verify.side_effect = OSError
        self.assertRaises(errors.Error, self._call,
                          self.dir, 0o700, os.geteuid(), False)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
