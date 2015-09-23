"""Registers and calls cleanup functions in case of an error."""
import os
import signal


_SIGNALS = ([signal.SIGTERM] if os.name == "nt" else
            [signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT,
             signal.SIGXCPU, signal.SIGXFSZ, signal.SIGPWR])


class ErrorHandler(object):
    """Registers and calls cleanup functions in case of an error."""
    def __init__(self, func=None):
        self.funcs = [func] if func else []
        self.prev_handlers = {}

    def __enter__(self):
        self.set_signal_handlers()

    def __exit__(self, exec_type, exec_value, traceback):
        if exec_value is not None:
            self.call_registered()
        self.reset_signal_handlers()

    def register(self, func):
        """Registers func to be called if an error occurs."""
        self.funcs.append(func)

    def call_registered(self):
        """Calls all functions in the order they were registered."""
        for func in self.funcs:
            func()

    def set_signal_handlers(self):
        """Sets signal handlers for signals in _SIGNALS."""
        for signum in _SIGNALS:
            prev_handler = signal.getsignal(signum)
            # If prev_handler is None, the handler was set outside of Python
            if prev_handler is not None:
                self.prev_handlers[signum] = prev_handler
                signal.signal(signum, self._signal_handler)

    def reset_signal_handlers(self):
        """Resets signal handlers for signals in _SIGNALS."""
        for signum in self.prev_handlers:
            signal.signal(signum, self.prev_handlers[signum])
        self.prev_handlers.clear()

    def _signal_handler(self, signum, _):
        """Calls registered functions and the previous signal handler.

        :param int signum: number of current signal

        """
        self.call_registered()
        signal.signal(signum, self.prev_handlers[signum])
        os.kill(os.getpid(), signum)
