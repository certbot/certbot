"""Tests for certbot.log."""
import logging
import logging.handlers
import os
import sys
import time
import unittest

import mock
import six

from acme import messages
from acme.magic_typing import Optional  # pylint: disable=unused-import, no-name-in-module

from certbot import compat
from certbot import constants
from certbot import errors
from certbot import util
from certbot.tests import util as test_util


class PreArgParseSetupTest(unittest.TestCase):
    """Tests for certbot.log.pre_arg_parse_setup."""

    @classmethod
    def _call(cls, *args, **kwargs):  # pylint: disable=unused-argument
        from certbot.log import pre_arg_parse_setup
        return pre_arg_parse_setup()

    @mock.patch('certbot.log.sys')
    @mock.patch('certbot.log.pre_arg_parse_except_hook')
    @mock.patch('certbot.log.logging.getLogger')
    @mock.patch('certbot.log.util.atexit_register')
    def test_it(self, mock_register, mock_get, mock_except_hook, mock_sys):
        mock_sys.argv = ['--debug']
        mock_sys.version_info = sys.version_info
        self._call()

        mock_root_logger = mock_get()
        mock_root_logger.setLevel.assert_called_once_with(logging.DEBUG)
        self.assertEqual(mock_root_logger.addHandler.call_count, 2)

        memory_handler = None  # type: Optional[logging.handlers.MemoryHandler]
        for call in mock_root_logger.addHandler.call_args_list:
            handler = call[0][0]
            if memory_handler is None and isinstance(handler, logging.handlers.MemoryHandler):
                memory_handler = handler
                target = memory_handler.target  # type: ignore
            else:
                self.assertTrue(isinstance(handler, logging.StreamHandler))
        self.assertTrue(
            isinstance(target, logging.StreamHandler))

        mock_register.assert_called_once_with(logging.shutdown)
        mock_sys.excepthook(1, 2, 3)
        mock_except_hook.assert_called_once_with(
            memory_handler, 1, 2, 3, debug=True, log_path=mock.ANY)


class PostArgParseSetupTest(test_util.ConfigTestCase):
    """Tests for certbot.log.post_arg_parse_setup."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import post_arg_parse_setup
        return post_arg_parse_setup(*args, **kwargs)

    def setUp(self):
        super(PostArgParseSetupTest, self).setUp()
        self.config.debug = False
        self.config.max_log_backups = 1000
        self.config.quiet = False
        self.config.verbose_count = constants.CLI_DEFAULTS['verbose_count']
        self.devnull = open(os.devnull, 'w')

        from certbot.log import ColoredStreamHandler
        self.stream_handler = ColoredStreamHandler(six.StringIO())
        from certbot.log import MemoryHandler, TempHandler
        self.temp_handler = TempHandler()
        self.temp_path = self.temp_handler.path
        self.memory_handler = MemoryHandler(self.temp_handler)
        self.root_logger = mock.MagicMock(
            handlers=[self.memory_handler, self.stream_handler])

    def tearDown(self):
        self.memory_handler.close()
        self.stream_handler.close()
        self.temp_handler.close()
        self.devnull.close()
        super(PostArgParseSetupTest, self).tearDown()

    def test_common(self):
        with mock.patch('certbot.log.logging.getLogger') as mock_get_logger:
            mock_get_logger.return_value = self.root_logger
            except_hook_path = 'certbot.log.post_arg_parse_except_hook'
            with mock.patch(except_hook_path) as mock_except_hook:
                with mock.patch('certbot.log.sys') as mock_sys:
                    mock_sys.version_info = sys.version_info
                    self._call(self.config)

        self.root_logger.removeHandler.assert_called_once_with(
            self.memory_handler)
        self.assertTrue(self.root_logger.addHandler.called)
        self.assertTrue(os.path.exists(os.path.join(
            self.config.logs_dir, 'letsencrypt.log')))
        self.assertFalse(os.path.exists(self.temp_path))
        mock_sys.excepthook(1, 2, 3)
        mock_except_hook.assert_called_once_with(
            1, 2, 3, debug=self.config.debug, log_path=self.config.logs_dir)

        level = self.stream_handler.level
        if self.config.quiet:
            self.assertEqual(level, constants.QUIET_LOGGING_LEVEL)
        else:
            self.assertEqual(level, -self.config.verbose_count * 10)

    def test_debug(self):
        self.config.debug = True
        self.test_common()

    def test_quiet(self):
        self.config.quiet = True
        self.test_common()


class SetupLogFileHandlerTest(test_util.ConfigTestCase):
    """Tests for certbot.log.setup_log_file_handler."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import setup_log_file_handler
        return setup_log_file_handler(*args, **kwargs)

    def setUp(self):
        super(SetupLogFileHandlerTest, self).setUp()
        self.config.max_log_backups = 42

    @mock.patch('certbot.main.logging.handlers.RotatingFileHandler')
    def test_failure(self, mock_handler):
        mock_handler.side_effect = IOError

        try:
            self._call(self.config, 'test.log', '%(message)s')
        except errors.Error as err:
            self.assertTrue('--logs-dir' in str(err))
        else:  # pragma: no cover
            self.fail('Error not raised.')

    def test_success_with_rollover(self):
        self._test_success_common(should_rollover=True)

    def test_success_without_rollover(self):
        self.config.max_log_backups = 0
        self._test_success_common(should_rollover=False)

    def _test_success_common(self, should_rollover):
        log_file = 'test.log'
        handler, log_path = self._call(self.config, log_file, '%(message)s')
        handler.close()

        self.assertEqual(handler.level, logging.DEBUG)
        self.assertEqual(handler.formatter.converter, time.localtime)

        expected_path = os.path.join(self.config.logs_dir, log_file)
        self.assertEqual(log_path, expected_path)

        backup_path = os.path.join(self.config.logs_dir, log_file + '.1')
        self.assertEqual(os.path.exists(backup_path), should_rollover)

    @mock.patch('certbot.log.logging.handlers.RotatingFileHandler')
    def test_max_log_backups_used(self, mock_handler):
        self._call(self.config, 'test.log', '%(message)s')
        backup_count = mock_handler.call_args[1]['backupCount']
        self.assertEqual(self.config.max_log_backups, backup_count)


class ColoredStreamHandlerTest(unittest.TestCase):
    """Tests for certbot.log.ColoredStreamHandler"""

    def setUp(self):
        self.stream = six.StringIO()
        self.stream.isatty = lambda: True
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)

        from certbot.log import ColoredStreamHandler
        self.handler = ColoredStreamHandler(self.stream)
        self.logger.addHandler(self.handler)

    def tearDown(self):
        self.handler.close()

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


class MemoryHandlerTest(unittest.TestCase):
    """Tests for certbot.log.MemoryHandler"""
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.msg = 'hi there'
        self.stream = six.StringIO()

        self.stream_handler = logging.StreamHandler(self.stream)
        from certbot.log import MemoryHandler
        self.handler = MemoryHandler(self.stream_handler)
        self.logger.addHandler(self.handler)

    def tearDown(self):
        self.handler.close()
        self.stream_handler.close()

    def test_flush(self):
        self._test_log_debug()
        self.handler.flush(force=True)
        self.assertEqual(self.stream.getvalue(), self.msg + '\n')

    def test_not_flushed(self):
        # By default, logging.ERROR messages and higher are flushed
        self.logger.critical(self.msg)
        self.handler.flush()
        self.assertEqual(self.stream.getvalue(), '')

    def test_target_reset(self):
        self._test_log_debug()

        new_stream = six.StringIO()
        new_stream_handler = logging.StreamHandler(new_stream)
        self.handler.setTarget(new_stream_handler)
        self.handler.flush(force=True)
        self.assertEqual(self.stream.getvalue(), '')
        self.assertEqual(new_stream.getvalue(), self.msg + '\n')
        new_stream_handler.close()

    def _test_log_debug(self):
        self.logger.debug(self.msg)


class TempHandlerTest(unittest.TestCase):
    """Tests for certbot.log.TempHandler."""
    def setUp(self):
        self.closed = False
        from certbot.log import TempHandler
        self.handler = TempHandler()

    def tearDown(self):
        self.handler.close()

    def test_permissions(self):
        self.assertTrue(
            util.check_permissions(self.handler.path, 0o600, compat.os_geteuid()))

    def test_delete(self):
        self.handler.close()
        self.assertFalse(os.path.exists(self.handler.path))

    def test_no_delete(self):
        self.handler.emit(mock.MagicMock())
        self.handler.close()
        self.assertTrue(os.path.exists(self.handler.path))
        os.remove(self.handler.path)


class PreArgParseExceptHookTest(unittest.TestCase):
    """Tests for certbot.log.pre_arg_parse_except_hook."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import pre_arg_parse_except_hook
        return pre_arg_parse_except_hook(*args, **kwargs)

    @mock.patch('certbot.log.post_arg_parse_except_hook')
    def test_it(self, mock_post_arg_parse_except_hook):
        # pylint: disable=star-args
        memory_handler = mock.MagicMock()
        args = ('some', 'args',)
        kwargs = {'some': 'kwargs'}

        self._call(memory_handler, *args, **kwargs)

        mock_post_arg_parse_except_hook.assert_called_once_with(
            *args, **kwargs)
        memory_handler.flush.assert_called_once_with(force=True)


class PostArgParseExceptHookTest(unittest.TestCase):
    """Tests for certbot.log.post_arg_parse_except_hook."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import post_arg_parse_except_hook
        return post_arg_parse_except_hook(*args, **kwargs)

    def setUp(self):
        self.error_msg = 'test error message'
        self.log_path = 'foo.log'

    def test_base_exception(self):
        exc_type = KeyboardInterrupt
        mock_logger, output = self._test_common(exc_type, debug=False)
        self._assert_exception_logged(mock_logger.error, exc_type)
        self._assert_logfile_output(output)

    def test_debug(self):
        exc_type = ValueError
        mock_logger, output = self._test_common(exc_type, debug=True)
        self._assert_exception_logged(mock_logger.error, exc_type)
        self._assert_logfile_output(output)

    def test_custom_error(self):
        exc_type = errors.PluginError
        mock_logger, output = self._test_common(exc_type, debug=False)
        self._assert_exception_logged(mock_logger.debug, exc_type)
        self._assert_quiet_output(mock_logger, output)

    def test_acme_error(self):
        # Get an arbitrary error code
        acme_code = next(six.iterkeys(messages.ERROR_CODES))

        def get_acme_error(msg):
            """Wraps ACME errors so the constructor takes only a msg."""
            return messages.Error.with_code(acme_code, detail=msg)

        mock_logger, output = self._test_common(get_acme_error, debug=False)
        self._assert_exception_logged(mock_logger.debug, messages.Error)
        self._assert_quiet_output(mock_logger, output)
        self.assertFalse(messages.ERROR_PREFIX in output)

    def test_other_error(self):
        exc_type = ValueError
        mock_logger, output = self._test_common(exc_type, debug=False)
        self._assert_exception_logged(mock_logger.debug, exc_type)
        self._assert_quiet_output(mock_logger, output)

    def _test_common(self, error_type, debug):
        """Returns the mocked logger and stderr output."""
        mock_err = six.StringIO()

        def write_err(*args, **unused_kwargs):
            """Write error to mock_err."""
            mock_err.write(args[0])

        try:
            raise error_type(self.error_msg)
        except BaseException:
            exc_info = sys.exc_info()
            with mock.patch('certbot.log.logger') as mock_logger:
                mock_logger.error.side_effect = write_err
                with mock.patch('certbot.log.sys.stderr', mock_err):
                    try:
                        # pylint: disable=star-args
                        self._call(
                            *exc_info, debug=debug, log_path=self.log_path)
                    except SystemExit as exit_err:
                        mock_err.write(str(exit_err))
                    else:  # pragma: no cover
                        self.fail('SystemExit not raised.')

        output = mock_err.getvalue()
        return mock_logger, output

    def _assert_exception_logged(self, log_func, exc_type):
        self.assertTrue(log_func.called)
        call_kwargs = log_func.call_args[1]
        self.assertTrue('exc_info' in call_kwargs)

        actual_exc_info = call_kwargs['exc_info']
        expected_exc_info = (exc_type, mock.ANY, mock.ANY)
        self.assertEqual(actual_exc_info, expected_exc_info)

    def _assert_logfile_output(self, output):
        self.assertTrue('Please see the logfile' in output)
        self.assertTrue(self.log_path in output)

    def _assert_quiet_output(self, mock_logger, output):
        self.assertFalse(mock_logger.exception.called)
        self.assertTrue(mock_logger.debug.called)
        self.assertTrue(self.error_msg in output)


class ExitWithLogPathTest(test_util.TempDirTestCase):
    """Tests for certbot.log.exit_with_log_path."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import exit_with_log_path
        return exit_with_log_path(*args, **kwargs)

    def test_log_file(self):
        log_file = os.path.join(self.tempdir, 'test.log')
        open(log_file, 'w').close()

        err_str = self._test_common(log_file)
        self.assertTrue('logfiles' not in err_str)
        self.assertTrue(log_file in err_str)

    def test_log_dir(self):
        err_str = self._test_common(self.tempdir)
        self.assertTrue('logfiles' in err_str)
        self.assertTrue(self.tempdir in err_str)

    def _test_common(self, *args, **kwargs):
        try:
            self._call(*args, **kwargs)
        except SystemExit as err:
            return str(err)
        else:  # pragma: no cover
            self.fail('SystemExit was not raised.')


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
