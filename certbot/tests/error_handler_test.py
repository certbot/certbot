"""Tests for certbot.error_handler."""
import contextlib
import os
import signal
import sys
import unittest
import traceback

import mock

def get_signals(signums):
    """Get the handlers for an iterable of signums."""
    return dict((s, signal.getsignal(s)) for s in signums)


def set_signals(sig_handler_dict):
    """Set the signal (keys) with the handler (values) from the input dict."""
    for s, h in sig_handler_dict.items():
        signal.signal(s, h)


@contextlib.contextmanager
def signal_receiver(signums):
    """Context manager to catch signals"""
    signals = []
    prev_handlers = {}
    prev_handlers = get_signals(signums)
    set_signals(dict((s, lambda s, _: signals.append(s)) for s in signums))
    yield signals
    set_signals(prev_handlers)


def send_signal(signum):
    """Send the given signal"""
    os.kill(os.getpid(), signum)


class ErrorHandlerTest(unittest.TestCase):
    """Tests for certbot.error_handler."""

    def setUp(self):
        from certbot import error_handler

        self.init_func = mock.MagicMock()
        self.init_args = set((42,))
        self.init_kwargs = {'foo': 'bar'}
        self.handler = error_handler.ErrorHandler(self.init_func,
                                                  *self.init_args,
                                                  **self.init_kwargs)
        # pylint: disable=protected-access
        self.signals = error_handler._SIGNALS

    def test_context_manager(self):
        exception_raised = False
        try:
            with self.handler:
                raise ValueError
        except ValueError:
            exception_raised = True

        self.assertTrue(exception_raised)
        self.init_func.assert_called_once_with(*self.init_args,
                                               **self.init_kwargs)

    def test_context_manager_with_signal(self):
        init_signals = get_signals(self.signals)
        with signal_receiver(self.signals) as signals_received:
            with self.handler:
                should_be_42 = 42
                send_signal(self.signals[0])
                should_be_42 *= 10

        # check exectuion stoped when the signal was sent
        self.assertEqual(42, should_be_42)
        # assert signals were caught
        self.assertEqual([self.signals[0]], signals_received)
        # assert the error handling function was just called once
        self.init_func.assert_called_once_with(*self.init_args,
                                               **self.init_kwargs)
        for signum in self.signals:
            self.assertEqual(init_signals[signum], signal.getsignal(signum))

    def test_bad_recovery(self):
        bad_func = mock.MagicMock(side_effect=[ValueError])
        self.handler.register(bad_func)
        try:
            with self.handler:
                raise ValueError
        except ValueError:
            pass
        self.init_func.assert_called_once_with(*self.init_args,
                                               **self.init_kwargs)
        bad_func.assert_called_once_with()

    def test_bad_recovery_with_signal(self):
        sig1 = self.signals[0]
        sig2 = self.signals[-1]
        bad_func = mock.MagicMock(side_effect=lambda: send_signal(sig1))
        self.handler.register(bad_func)
        with signal_receiver(self.signals) as signals_received:
            with self.handler:
                send_signal(sig2)
        self.assertEqual([sig2, sig1], signals_received)
        self.init_func.assert_called_once_with(*self.init_args,
                                               **self.init_kwargs)
        bad_func.assert_called_once_with()

    def test_sysexit_ignored(self):
        try:
            with self.handler:
                sys.exit(0)
        except SystemExit:
            pass
        self.assertFalse(self.init_func.called)

    @mock.patch('certbot.main.sys')
    def test_handle_exception(self, mock_sys):
        # pylint: disable=protected-access
        from acme import messages
        from certbot import main
        from certbot import errors

        config = mock.MagicMock()
        mock_open = mock.mock_open()

        with mock.patch('certbot.main.open', mock_open, create=True):
            exception = Exception('detail')
            config.verbose_count = 1
            main._handle_exception(
                Exception, exc_value=exception, trace=None, config=None)
            mock_open().write.assert_any_call(''.join(
                traceback.format_exception_only(Exception, exception)))
            error_msg = mock_sys.exit.call_args_list[0][0][0]
            self.assertTrue('unexpected error' in error_msg)

        with mock.patch('certbot.main.open', mock_open, create=True):
            mock_open.side_effect = [KeyboardInterrupt]
            error = errors.Error('detail')
            main._handle_exception(
                errors.Error, exc_value=error, trace=None, config=None)
            # assert_any_call used because sys.exit doesn't exit in cli.py
            mock_sys.exit.assert_any_call(''.join(
                traceback.format_exception_only(errors.Error, error)))

        bad_typ = messages.ERROR_PREFIX + 'triffid'
        exception = messages.Error(detail='alpha', typ=bad_typ, title='beta')
        config = mock.MagicMock(debug=False, verbose_count=-3)
        main._handle_exception(
            messages.Error, exc_value=exception, trace=None, config=config)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' not in error_msg)
        self.assertTrue('alpha' in error_msg)
        self.assertTrue('beta' in error_msg)
        config = mock.MagicMock(debug=False, verbose_count=1)
        main._handle_exception(
            messages.Error, exc_value=exception, trace=None, config=config)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' in error_msg)
        self.assertTrue('alpha' in error_msg)

        interrupt = KeyboardInterrupt('detail')
        main._handle_exception(
            KeyboardInterrupt, exc_value=interrupt, trace=None, config=None)
        mock_sys.exit.assert_called_with(''.join(
            traceback.format_exception_only(KeyboardInterrupt, interrupt)))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
