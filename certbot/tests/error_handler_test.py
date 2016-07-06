"""Tests for certbot.error_handler."""
import contextlib
import os
import signal
import sys
import unittest

import mock


@contextlib.contextmanager
def signal_receiver(signums):
    """Context manager to catch signals"""
    signals = []
    prev_handlers = {}
    for signum in signums:
        prev_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, lambda signum, _: signals.append(signum))
    yield signals
    for signum in signums:
        signal.signal(signum, prev_handlers[signum])


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
        try:
            with self.handler:
                raise ValueError
        except ValueError:
            exception_raised = True

        self.assertTrue(exception_raised)
        self.init_func.assert_called_once_with(*self.init_args,
                                               **self.init_kwargs)

    def test_context_manager_with_signal(self):
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
            sig = signal.getsignal(signum)
            self.assertTrue((sig == signal.SIG_DFL) or (sig == signal.SIG_IGN))

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


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
