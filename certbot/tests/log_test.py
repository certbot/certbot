"""Tests for certbot.log."""
import logging
import traceback
import logging.handlers
import os
import sys
import time
import unittest

import mock
import six

from acme import messages

from certbot import constants
from certbot import errors
from certbot import util
from certbot.tests import util as test_util


class PreArgSetupTest(unittest.TestCase):
    """Tests for certbot.log.pre_arg_setup."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import pre_arg_setup
        return pre_arg_setup(*args, **kwargs)

    def test_it(self):
        with mock.patch('certbot.log.except_hook') as mock_except_hook:
            with mock.patch('certbot.log.sys') as mock_sys:
                self._call()

        mock_sys.excepthook(1, 2, 3)
        mock_except_hook.assert_called_once_with(1, 2, 3, config=None)


class PostArgSetupTest(test_util.TempDirTestCase):
    """Tests for certbot.log.post_arg_setup."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import post_arg_setup
        return post_arg_setup(*args, **kwargs)

    def setUp(self):
        super(PostArgSetupTest, self).setUp()
        self.config = mock.MagicMock(
            logs_dir=self.tempdir, quiet=False,
            verbose_count=constants.CLI_DEFAULTS['verbose_count'])
        self.root_logger = mock.MagicMock()

    def test_common(self):
        with mock.patch('certbot.log.logging.getLogger') as mock_get_logger:
            mock_get_logger.return_value = self.root_logger
            with mock.patch('certbot.log.except_hook') as mock_except_hook:
                with mock.patch('certbot.log.sys') as mock_sys:
                    mock_sys.version_info = sys.version_info
                    self._call(self.config)

        self.assertEqual(self.root_logger.addHandler.call_count, 2)
        self.assertTrue(os.path.exists(os.path.join(
            self.config.logs_dir, 'letsencrypt.log')))
        mock_sys.excepthook(1, 2, 3)
        mock_except_hook.assert_called_once_with(1, 2, 3, config=self.config)

        stderr_handler = self.root_logger.addHandler.call_args_list[0][0][0]
        level = stderr_handler.level
        if self.config.quiet:
            self.assertEqual(level, constants.QUIET_LOGGING_LEVEL)
        else:
            self.assertEqual(level, -self.config.verbose_count * 10)

    def test_quiet(self):
        self.config.quiet = True
        self.test_common()


class SetupLogFileHandlerTest(test_util.TempDirTestCase):
    """Tests for certbot.log.setup_log_file_handler."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import setup_log_file_handler
        return setup_log_file_handler(*args, **kwargs)

    def setUp(self):
        super(SetupLogFileHandlerTest, self).setUp()

        self.config = mock.Mock(spec_set=['logs_dir'],
                                logs_dir=self.tempdir)

    def test_failure(self):
        self.config.logs_dir = os.path.join(self.config.logs_dir, 'test.log')
        open(self.config.logs_dir, 'w').close()

        try:
            self._call(self.config, 'test.log', '%(message)s')
        except errors.Error as err:
            self.assertTrue('--logs-dir' in str(err))
        else:  # pragma: no cover
            self.fail('Error not raised.')

    def test_success(self):
        log_file = 'test.log'
        handler, log_path = self._call(self.config, log_file, '%(message)s')
        self.assertEqual(handler.level, logging.DEBUG)
        self.assertEqual(handler.formatter.converter, time.gmtime)

        expected_path = os.path.join(self.config.logs_dir, log_file)
        self.assertEqual(log_path, expected_path)


class ColoredStreamHandlerTest(unittest.TestCase):
    """Tests for certbot.log."""

    def setUp(self):
        from certbot import log

        self.stream = six.StringIO()
        self.stream.isatty = lambda: True
        self.handler = log.ColoredStreamHandler(self.stream)

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.handler)

    def test_format(self):
        msg = 'I did a thing'
        self.logger.debug(msg)
        self.assertEqual(self.stream.getvalue(), '{0}\n'.format(msg))

    def test_format_and_red_level(self):
        msg = 'I did another thing'
        self.handler.red_level = logging.DEBUG
        self.logger.debug(msg)

        self.assertEqual(self.stream.getvalue(),
                         '{0}{1}{2}\n'.format(util.ANSI_SGR_RED,
                                              msg,
                                              util.ANSI_SGR_RESET))


class ExceptHookTest(unittest.TestCase):
    """Tests for certbot.log.except_hook."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import except_hook
        return except_hook(*args, **kwargs)

    @mock.patch('certbot.log.sys')
    def test_except_hook(self, mock_sys):
        config = mock.MagicMock()
        mock_open = mock.mock_open()

        with mock.patch('certbot.log.open', mock_open, create=True):
            exception = Exception('detail')
            config.verbose_count = 1
            self._call(
                Exception, exc_value=exception, trace=None, config=None)
            mock_open().write.assert_any_call(''.join(
                traceback.format_exception_only(Exception, exception)))
            error_msg = mock_sys.exit.call_args_list[0][0][0]
            self.assertTrue('unexpected error' in error_msg)

        with mock.patch('certbot.log.open', mock_open, create=True):
            mock_open.side_effect = [KeyboardInterrupt]
            error = errors.Error('detail')
            self._call(
                errors.Error, exc_value=error, trace=None, config=None)
            # assert_any_call used because sys.exit doesn't exit in cli.py
            mock_sys.exit.assert_any_call(''.join(
                traceback.format_exception_only(errors.Error, error)))

        bad_typ = messages.ERROR_PREFIX + 'triffid'
        exception = messages.Error(detail='alpha', typ=bad_typ, title='beta')
        config = mock.MagicMock(debug=False, verbose_count=-3)
        self._call(
            messages.Error, exc_value=exception, trace=None, config=config)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' not in error_msg)
        self.assertTrue('alpha' in error_msg)
        self.assertTrue('beta' in error_msg)
        config = mock.MagicMock(debug=False, verbose_count=1)
        self._call(
            messages.Error, exc_value=exception, trace=None, config=config)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' in error_msg)
        self.assertTrue('alpha' in error_msg)

        interrupt = KeyboardInterrupt('detail')
        self._call(
            KeyboardInterrupt, exc_value=interrupt, trace=None, config=None)
        mock_sys.exit.assert_called_with(''.join(
            traceback.format_exception_only(KeyboardInterrupt, interrupt)))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
