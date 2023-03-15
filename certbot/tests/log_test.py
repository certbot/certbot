"""Tests for certbot._internal.log."""
import io
import logging
import logging.handlers
import sys
import time
from typing import Callable, Tuple, Type, Union, Optional
import unittest
from unittest import mock

import pytest

from acme import messages
from certbot import errors
from certbot import util
from certbot._internal import constants
from certbot.compat import filesystem
from certbot.compat import os
from certbot.tests import util as test_util
from unittest.mock import MagicMock


class PreArgParseSetupTest(unittest.TestCase):
    """Tests for certbot._internal.log.pre_arg_parse_setup."""

    @classmethod
    def _call(cls, *args, **kwargs) -> None:  # pylint: disable=unused-argument
        from certbot._internal.log import pre_arg_parse_setup
        return pre_arg_parse_setup()

    def tearDown(self) -> None:
        # We need to call logging.shutdown() at the end of this test to
        # properly clean up any resources created by pre_arg_parse_setup.
        logging.shutdown()
        super().tearDown()

    @mock.patch('certbot._internal.log.sys')
    @mock.patch('certbot._internal.log.pre_arg_parse_except_hook')
    @mock.patch('certbot._internal.log.logging.getLogger')
    @mock.patch('certbot._internal.log.util.atexit_register')
    def test_it(self, mock_register: MagicMock, mock_get: MagicMock, mock_except_hook: MagicMock, mock_sys: MagicMock) -> None:
        mock_sys.argv = ['--debug']
        mock_sys.version_info = sys.version_info
        self._call()

        mock_root_logger = mock_get()
        mock_root_logger.setLevel.assert_called_once_with(logging.DEBUG)
        assert mock_root_logger.addHandler.call_count == 2

        memory_handler: Optional[logging.handlers.MemoryHandler] = None
        for call in mock_root_logger.addHandler.call_args_list:
            handler = call[0][0]
            if memory_handler is None and isinstance(handler, logging.handlers.MemoryHandler):
                memory_handler = handler
                target = memory_handler.target
            else:
                assert isinstance(handler, logging.StreamHandler)
        assert isinstance(target, logging.StreamHandler)

        mock_register.assert_called_once_with(logging.shutdown)
        mock_sys.excepthook(1, 2, 3)
        mock_except_hook.assert_called_once_with(
            memory_handler, 1, 2, 3, debug=True, quiet=False, log_path=mock.ANY)


class PostArgParseSetupTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.log.post_arg_parse_setup."""

    @classmethod
    def _call(cls, *args, **kwargs) -> None:
        from certbot._internal.log import post_arg_parse_setup
        return post_arg_parse_setup(*args, **kwargs)

    def setUp(self) -> None:
        super().setUp()
        self.config.debug = False
        self.config.max_log_backups = 1000
        self.config.quiet = False
        self.config.verbose_count = constants.CLI_DEFAULTS['verbose_count']
        self.devnull = open(os.devnull, 'w')

        from certbot._internal.log import ColoredStreamHandler
        self.stream_handler = ColoredStreamHandler(io.StringIO())
        from certbot._internal.log import MemoryHandler
        from certbot._internal.log import TempHandler
        self.temp_handler = TempHandler()
        self.temp_path = self.temp_handler.path
        self.memory_handler = MemoryHandler(self.temp_handler)
        self.root_logger = mock.MagicMock(
            handlers=[self.memory_handler, self.stream_handler])

    def tearDown(self) -> None:
        self.memory_handler.close()
        self.stream_handler.close()
        self.temp_handler.close()
        self.devnull.close()
        super().tearDown()

    def test_common(self) -> None:
        with mock.patch('certbot._internal.log.logging.getLogger') as mock_get_logger:
            mock_get_logger.return_value = self.root_logger
            except_hook_path = 'certbot._internal.log.post_arg_parse_except_hook'
            with mock.patch(except_hook_path) as mock_except_hook:
                with mock.patch('certbot._internal.log.sys') as mock_sys:
                    mock_sys.version_info = sys.version_info
                    self._call(self.config)

        log_path = os.path.join(self.config.logs_dir, 'letsencrypt.log')

        self.root_logger.removeHandler.assert_called_once_with(
            self.memory_handler)
        assert self.root_logger.addHandler.called
        assert os.path.exists(log_path)
        assert not os.path.exists(self.temp_path)
        mock_sys.excepthook(1, 2, 3)
        mock_except_hook.assert_called_once_with(
            1, 2, 3, debug=self.config.debug,
            quiet=self.config.quiet, log_path=log_path)

        level = self.stream_handler.level
        if self.config.quiet:
            assert level == constants.QUIET_LOGGING_LEVEL
        else:
            assert level == constants.DEFAULT_LOGGING_LEVEL

    def test_debug(self) -> None:
        self.config.debug = True
        self.test_common()

    def test_quiet(self) -> None:
        self.config.quiet = True
        self.test_common()


class SetupLogFileHandlerTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.log.setup_log_file_handler."""

    @classmethod
    def _call(cls, *args, **kwargs) -> Union[Tuple[MagicMock, str], Tuple[    logging.handlers.RotatingFileHandler, str]]:
        from certbot._internal.log import setup_log_file_handler
        return setup_log_file_handler(*args, **kwargs)

    def setUp(self) -> None:
        super().setUp()
        self.config.max_log_backups = 42

    @mock.patch('certbot._internal.main.logging.handlers.RotatingFileHandler')
    def test_failure(self, mock_handler: MagicMock) -> None:
        mock_handler.side_effect = IOError

        try:
            self._call(self.config, 'test.log', '%(message)s')
        except errors.Error as err:
            assert '--logs-dir' in str(err)
        else:  # pragma: no cover
            self.fail('Error not raised.')

    def test_success_with_rollover(self) -> None:
        self._test_success_common(should_rollover=True)

    def test_success_without_rollover(self) -> None:
        self.config.max_log_backups = 0
        self._test_success_common(should_rollover=False)

    def _test_success_common(self, should_rollover: bool) -> None:
        log_file = 'test.log'
        handler, log_path = self._call(self.config, log_file, '%(message)s')
        handler.close()

        assert handler.level == logging.DEBUG
        assert handler.formatter.converter == time.localtime

        expected_path = os.path.join(self.config.logs_dir, log_file)
        assert log_path == expected_path

        backup_path = os.path.join(self.config.logs_dir, log_file + '.1')
        assert os.path.exists(backup_path) == should_rollover

    @mock.patch('certbot._internal.log.logging.handlers.RotatingFileHandler')
    def test_max_log_backups_used(self, mock_handler: MagicMock) -> None:
        self._call(self.config, 'test.log', '%(message)s')
        backup_count = mock_handler.call_args[1]['backupCount']
        assert self.config.max_log_backups == backup_count


class ColoredStreamHandlerTest(unittest.TestCase):
    """Tests for certbot._internal.log.ColoredStreamHandler"""

    def setUp(self) -> None:
        self.stream = io.StringIO()
        self.stream.isatty = lambda: True
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)

        from certbot._internal.log import ColoredStreamHandler
        self.handler = ColoredStreamHandler(self.stream)
        self.logger.addHandler(self.handler)

    def tearDown(self) -> None:
        self.handler.close()

    def test_format(self) -> None:
        msg = 'I did a thing'
        self.logger.debug(msg)
        assert self.stream.getvalue() == '{0}\n'.format(msg)

    def test_format_and_red_level(self) -> None:
        msg = 'I did another thing'
        self.handler.red_level = logging.DEBUG
        self.logger.debug(msg)

        assert self.stream.getvalue() == \
                         '{0}{1}{2}\n'.format(util.ANSI_SGR_RED,
                                              msg,
                                              util.ANSI_SGR_RESET)


class MemoryHandlerTest(unittest.TestCase):
    """Tests for certbot._internal.log.MemoryHandler"""
    def setUp(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.msg = 'hi there'
        self.stream = io.StringIO()

        self.stream_handler = logging.StreamHandler(self.stream)
        from certbot._internal.log import MemoryHandler
        self.handler = MemoryHandler(self.stream_handler)
        self.logger.addHandler(self.handler)

    def tearDown(self) -> None:
        self.handler.close()
        self.stream_handler.close()

    def test_flush(self) -> None:
        self._test_log_debug()
        self.handler.flush(force=True)
        assert self.stream.getvalue() == self.msg + '\n'

    def test_not_flushed(self) -> None:
        # By default, logging.ERROR messages and higher are flushed
        self.logger.critical(self.msg)
        self.handler.flush()
        assert self.stream.getvalue() == ''

    def test_target_reset(self) -> None:
        self._test_log_debug()

        new_stream = io.StringIO()
        new_stream_handler = logging.StreamHandler(new_stream)
        self.handler.setTarget(new_stream_handler)
        self.handler.flush(force=True)
        assert self.stream.getvalue() == ''
        assert new_stream.getvalue() == self.msg + '\n'
        new_stream_handler.close()

    def _test_log_debug(self) -> None:
        self.logger.debug(self.msg)


class TempHandlerTest(unittest.TestCase):
    """Tests for certbot._internal.log.TempHandler."""
    def setUp(self) -> None:
        self.closed = False
        from certbot._internal.log import TempHandler
        self.handler = TempHandler()

    def tearDown(self) -> None:
        self.handler.close()

    def test_permissions(self) -> None:
        assert filesystem.check_permissions(self.handler.path, 0o600)

    def test_delete(self) -> None:
        self.handler.close()
        assert not os.path.exists(self.handler.path)

    def test_no_delete(self) -> None:
        self.handler.emit(mock.MagicMock())
        self.handler.close()
        assert os.path.exists(self.handler.path)
        os.remove(self.handler.path)


class PreArgParseExceptHookTest(unittest.TestCase):
    """Tests for certbot._internal.log.pre_arg_parse_except_hook."""
    @classmethod
    def _call(cls, *args, **kwargs) -> None:
        from certbot._internal.log import pre_arg_parse_except_hook
        return pre_arg_parse_except_hook(*args, **kwargs)

    @mock.patch('certbot._internal.log.post_arg_parse_except_hook')
    def test_it(self, mock_post_arg_parse_except_hook: MagicMock) -> None:
        memory_handler = mock.MagicMock()
        args = ('some', 'args',)
        kwargs = {'some': 'kwargs'}

        self._call(memory_handler, *args, **kwargs)

        mock_post_arg_parse_except_hook.assert_called_once_with(
            *args, **kwargs)
        memory_handler.flush.assert_called_once_with(force=True)


class PostArgParseExceptHookTest(unittest.TestCase):
    """Tests for certbot._internal.log.post_arg_parse_except_hook."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.log import post_arg_parse_except_hook
        return post_arg_parse_except_hook(*args, **kwargs)

    def setUp(self) -> None:
        self.error_msg = 'test error message'
        self.log_path = 'foo.log'

    def test_base_exception(self) -> None:
        exc_type = BaseException
        mock_logger, output = self._test_common(exc_type, debug=False)
        self._assert_exception_logged(mock_logger.error, exc_type)
        self._assert_logfile_output(output)

    def test_debug(self) -> None:
        exc_type = ValueError
        mock_logger, output = self._test_common(exc_type, debug=True)
        self._assert_exception_logged(mock_logger.error, exc_type)
        self._assert_logfile_output(output)

    def test_quiet(self) -> None:
        exc_type = ValueError
        mock_logger, output = self._test_common(exc_type, debug=True, quiet=True)
        self._assert_exception_logged(mock_logger.error, exc_type)
        assert 'See the logfile' not in output

    def test_custom_error(self) -> None:
        exc_type = errors.PluginError
        mock_logger, output = self._test_common(exc_type, debug=False)
        self._assert_exception_logged(mock_logger.debug, exc_type)
        self._assert_quiet_output(mock_logger, output)

    def test_acme_error(self) -> None:
        # Get an arbitrary error code
        acme_code = next(iter(messages.ERROR_CODES))

        def get_acme_error(msg):
            """Wraps ACME errors so the constructor takes only a msg."""
            return messages.Error.with_code(acme_code, detail=msg)

        mock_logger, output = self._test_common(get_acme_error, debug=False)
        self._assert_exception_logged(mock_logger.debug, messages.Error)
        self._assert_quiet_output(mock_logger, output)
        assert messages.ERROR_PREFIX not in output

    def test_other_error(self) -> None:
        exc_type = ValueError
        mock_logger, output = self._test_common(exc_type, debug=False)
        self._assert_exception_logged(mock_logger.debug, exc_type)
        self._assert_quiet_output(mock_logger, output)

    def test_keyboardinterrupt(self) -> None:
        exc_type = KeyboardInterrupt
        mock_logger, output = self._test_common(exc_type, debug=False)
        mock_logger.error.assert_called_once_with('Exiting due to user request.')

    def _test_common(self, error_type: Union[Type[BaseException], Callable], debug: bool, quiet: bool=False) -> Tuple[MagicMock, str]:
        """Returns the mocked logger and stderr output."""
        mock_err = io.StringIO()

        def write_err(*args, **unused_kwargs):
            """Write error to mock_err."""
            mock_err.write(args[0])

        try:
            raise error_type(self.error_msg)
        except BaseException:
            exc_info = sys.exc_info()
            with mock.patch('certbot._internal.log.logger') as mock_logger:
                mock_logger.error.side_effect = write_err
                with mock.patch('certbot._internal.log.sys.stderr', mock_err):
                    try:
                        self._call(
                            *exc_info, debug=debug, quiet=quiet, log_path=self.log_path)
                    except SystemExit as exit_err:
                        mock_err.write(str(exit_err))
                    else:  # pragma: no cover
                        self.fail('SystemExit not raised.')

        output = mock_err.getvalue()
        return mock_logger, output

    def _assert_exception_logged(self, log_func: MagicMock, exc_type: Type[BaseException]) -> None:
        assert log_func.called
        call_kwargs = log_func.call_args[1]
        assert 'exc_info' in call_kwargs

        actual_exc_info = call_kwargs['exc_info']
        expected_exc_info = (exc_type, mock.ANY, mock.ANY)
        assert actual_exc_info == expected_exc_info

    def _assert_logfile_output(self, output: str) -> None:
        assert 'See the logfile' in output
        assert self.log_path in output

    def _assert_quiet_output(self, mock_logger: MagicMock, output: str) -> None:
        assert mock_logger.exception.called is False
        assert mock_logger.debug.called
        assert self.error_msg in output


class ExitWithAdviceTest(test_util.TempDirTestCase):
    """Tests for certbot._internal.log.exit_with_advice."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.log import exit_with_advice
        return exit_with_advice(*args, **kwargs)

    def test_log_file(self) -> None:
        log_file = os.path.join(self.tempdir, 'test.log')
        open(log_file, 'w').close()

        err_str = self._test_common(log_file)
        assert 'logfiles' not in err_str
        assert log_file in err_str

    def test_log_dir(self) -> None:
        err_str = self._test_common(self.tempdir)
        assert 'logfiles' in err_str
        assert self.tempdir in err_str

    # pylint: disable=inconsistent-return-statements
    def _test_common(self, *args, **kwargs) -> str:
        try:
            self._call(*args, **kwargs)
        except SystemExit as err:
            return str(err)
        self.fail('SystemExit was not raised.')  # pragma: no cover


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
