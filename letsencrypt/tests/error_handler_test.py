"""Tests for letsencrypt.error_handler."""
import signal
import unittest

import mock

from letsencrypt import error_handler


class ErrorHandlerTest(unittest.TestCase):
    """Tests for letsencrypt.error_handler."""

    def setUp(self):
        self.init_func = mock.MagicMock()
        self.handler = error_handler.ErrorHandler(self.init_func)

    def test_context_manager(self):
        try:
            with self.handler:
                raise ValueError
        except ValueError:
            pass
        self.init_func.assert_called_once_with()

    @mock.patch('letsencrypt.error_handler.os')
    @mock.patch('letsencrypt.error_handler.signal')
    def test_signal_handler(self, mock_signal, mock_os):
        # pylint: disable=protected-access
        mock_signal.getsignal.return_value = signal.SIG_DFL
        self.handler.set_signal_handlers()
        signal_handler = self.handler._signal_handler
        for signum in error_handler._SIGNALS:
            mock_signal.signal.assert_any_call(signum, signal_handler)

        signum = error_handler._SIGNALS[0]
        signal_handler(signum, None)
        self.init_func.assert_called_once_with()
        mock_os.kill.assert_called_once_with(mock_os.getpid(), signum)

        self.handler.reset_signal_handlers()
        for signum in error_handler._SIGNALS:
            mock_signal.signal.assert_any_call(signum, signal.SIG_DFL)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
