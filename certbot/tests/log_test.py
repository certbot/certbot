"""Tests for certbot.log."""
import logging
import traceback
import unittest

import mock
import six

from acme import messages

from certbot import errors
from certbot import util


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
    """Test log.except_hook"""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.log import except_hook
        return except_hook(*args, **kwargs)

    @mock.patch('certbot.log.sys')
    def test_handle_exception(self, mock_sys):
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
