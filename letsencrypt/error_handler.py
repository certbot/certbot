"""Registers functions to be called if an exception or signal occurs."""
import logging
import os
import signal
import traceback


logger = logging.getLogger(__name__)


# _SIGNALS stores the signals that will be handled by the ErrorHandler. These
# signals were chosen as their default handler terminates the process and could
# potentially occur from inside Python. Signals such as SIGILL were not
# included as they could be a sign of something devious and we should terminate
# immediately.
_SIGNALS = ([signal.SIGTERM] if os.name == "nt" else
            [signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT,
             signal.SIGXCPU, signal.SIGXFSZ])


class ErrorHandler(object):
    """Registers functions to be called if an exception or signal occurs.

    This class allows you to register functions that will be called when
    an exception (excluding SystemExit) or signal is encountered. The
    class works best as a context manager. For example:

    with ErrorHandler(cleanup_func):
        do_something()

    If an exception is raised out of do_something, cleanup_func will be
    called. The exception is not caught by the ErrorHandler. Similarly,
    if a signal is encountered, cleanup_func is called followed by the
    previously registered signal handler.

    Every registered function is attempted to be run to completion
    exactly once. If a registered function raises an exception, it is
    logged and the next function is called. If a (different) handled
    signal occurs while calling a registered function, it is attempted
    to be called again by the next signal handler.

    """
    def __init__(self, func=None):
        self.funcs = []
        self.prev_handlers = {}
        if func is not None:
            self.register(func)

    def __enter__(self):
        self.set_signal_handlers()

    def __exit__(self, exec_type, exec_value, trace):
        # SystemExit is ignored to properly handle forks that don't exec
        if exec_type not in (None, SystemExit):
            logger.debug("Encountered exception:\n%s", "".join(
                traceback.format_exception(exec_type, exec_value, trace)))
            self.call_registered()
        self.reset_signal_handlers()

    def register(self, func):
        """Registers func to be called if an error occurs."""
        self.funcs.append(func)

    def call_registered(self):
        """Calls all registered functions"""
        logger.debug("Calling registered functions")
        while self.funcs:
            try:
                self.funcs[-1]()
            except Exception as error:  # pylint: disable=broad-except
                logger.error("Encountered exception during recovery")
                logger.exception(error)
            self.funcs.pop()

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

    def _signal_handler(self, signum, unused_frame):
        """Calls registered functions and the previous signal handler.

        :param int signum: number of current signal

        """
        logger.debug("Singal %s encountered", signum)
        self.call_registered()
        signal.signal(signum, self.prev_handlers[signum])
        os.kill(os.getpid(), signum)
