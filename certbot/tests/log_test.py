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

from certbot import constants
from certbot import errors
from certbot import util
from certbot.tests import util as test_util


class PreArgParseSetupTest(unittest.TestCase):
    """Tests for certbot.log.pre_arg_parse_setup."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import pre_arg_parse_setup
        return pre_arg_parse_setup(*args, **kwargs)

    @mock.patch('certbot.log.sys')
    @mock.patch('certbot.log.except_hook')
    @mock.patch('certbot.log.logging.getLogger')
    @mock.patch('certbot.log.util.atexit_register')
    def test_it(self, mock_register, mock_get, mock_except_hook, mock_sys):
        mock_sys.argv = ['--debug']
        mock_sys.version_info = sys.version_info
        self._call()

        mock_register.assert_called_once_with(logging.shutdown)
        mock_sys.excepthook(1, 2, 3)
        mock_except_hook.assert_called_once_with(
            1, 2, 3, debug=True, log_path=mock.ANY)

        mock_root_logger = mock_get()
        mock_root_logger.setLevel.assert_called_once_with(logging.DEBUG)
        self.assertEqual(mock_root_logger.addHandler.call_count, 2)

        MemoryHandler = logging.handlers.MemoryHandler
        memory_handler = None
        for call in mock_root_logger.addHandler.call_args_list:
            handler = call[0][0]
            if memory_handler is None and isinstance(handler, MemoryHandler):
                memory_handler = handler
            else:
                self.assertTrue(isinstance(handler, logging.StreamHandler))
        self.assertTrue(
            isinstance(memory_handler.target, logging.StreamHandler))


class PostArgParseSetupTest(test_util.TempDirTestCase):
    """Tests for certbot.log.post_arg_parse_setup."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import post_arg_parse_setup
        return post_arg_parse_setup(*args, **kwargs)

    def setUp(self):
        super(PostArgParseSetupTest, self).setUp()
        self.config = mock.MagicMock(
            debug=False, logs_dir=self.tempdir, quiet=False,
            verbose_count=constants.CLI_DEFAULTS['verbose_count'])
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
        super(PostArgParseSetupTest, self).tearDown()

    def test_common(self):
        with mock.patch('certbot.log.logging.getLogger') as mock_get_logger:
            mock_get_logger.return_value = self.root_logger
            with mock.patch('certbot.log.except_hook') as mock_except_hook:
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
            1, 2, 3, debug=self.config.debug, log_path=self.tempdir)

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


class SetupLogFileHandlerTest(test_util.TempDirTestCase):
    """Tests for certbot.log.setup_log_file_handler."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import setup_log_file_handler
        return setup_log_file_handler(*args, **kwargs)

    def setUp(self):
        super(SetupLogFileHandlerTest, self).setUp()
        self.config = mock.MagicMock(logs_dir=self.tempdir)

    @mock.patch('certbot.main.logging.handlers.RotatingFileHandler')
    def test_failure(self, mock_handler):
        mock_handler.side_effect = IOError

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
        handler.close()


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
        self.handler.flush()
        self.assertEqual(self.stream.getvalue(), self.msg + '\n')

    def test_not_flushed(self):
        # By default, logging.ERROR messages and higher are flushed
        self.logger.critical(self.msg)
        self.assertEqual(self.stream.getvalue(), '')

    def test_target_reset(self):
        self._test_log_debug()

        new_stream = six.StringIO()
        new_stream_handler = logging.StreamHandler(new_stream)
        self.handler.setTarget(new_stream_handler)
        self.handler.flush()
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
        if not self.closed:
            self.handler.delete_and_close()

    def test_permissions(self):
        self.assertTrue(
            util.check_permissions(self.handler.path, 0o600, os.getuid()))

    def test_delete(self):
        self.handler.delete_and_close()
        self.closed = True
        self.assertFalse(os.path.exists(self.handler.path))

    def test_no_delete(self):
        self.handler.close()
        self.closed = True
        self.assertTrue(os.path.exists(self.handler.path))
        os.remove(self.handler.path)


class ExceptHookTest(unittest.TestCase):
    """Tests for certbot.log.except_hook."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import except_hook
        return except_hook(*args, **kwargs)

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
        try:
            raise error_type(self.error_msg)
        except BaseException:
            exc_info = sys.exc_info()
            with mock.patch('certbot.log.logger') as mock_logger:
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
