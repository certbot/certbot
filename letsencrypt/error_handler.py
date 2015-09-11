"""Registers and calls cleanup functions in case of an error."""
import os
import signal


_SIGNALS = [signal.SIGTERM] if os.name == "nt" else
           [signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT,
            signal.SIGXCPU, signal.SIGXFSZ, signal.SIGPWR,]


class ErrorHandler():
    """Registers and calls cleanup functions in case of an error."""
    def __init__(self, func=None):
        self.funcs = []
        if func:
            self.funcs.append(func)

    def __enter__(self):
        self.set_signal_handlers()

    def __exit__(self, exec_type, exec_value, traceback):
        if exec_value is not None:
            self.cleanup()
        self.reset_signal_handlers()

    def register(self, func):
        """Registers func to be called if an error occurs."""
        self.funcs.append(func)
    
    def cleanup(self):
        """Calls all registered functions."""
        while self.funcs:
            self.funcs.pop()()

    def set_signal_handlers(self):
        for signal_type in _SIGNALS:
            signal.signal(signal_type, self._signal_handler)

    def reset_signal_handlers(self):
        for signal_type in _SIGNALS:
            signal.signal(signal_type, signal.SIG_DFL)

    def _signal_handler(self, signum, frame):
        self.cleanup()
        signal.signal(signal_type, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
