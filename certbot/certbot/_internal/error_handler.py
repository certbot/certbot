"""Registers functions to be called if an exception or signal occurs."""
import functools
import logging
import signal
import traceback
from types import TracebackType
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Type
from typing import Union

from certbot import errors
from certbot.compat import os

logger = logging.getLogger(__name__)


# _SIGNALS stores the signals that will be handled by the ErrorHandler. These
# signals were chosen as their default handler terminates the process and could
# potentially occur from inside Python. Signals such as SIGILL were not
# included as they could be a sign of something devious and we should terminate
# immediately.
if os.name != "nt":
    _SIGNALS = [signal.SIGTERM]
    for signal_code in [signal.SIGHUP, signal.SIGQUIT,
                        signal.SIGXCPU, signal.SIGXFSZ]:
        # Adding only those signals that their default action is not Ignore.
        # This is platform-dependent, so we check it dynamically.
        if signal.getsignal(signal_code) != signal.SIG_IGN:
            _SIGNALS.append(signal_code)
else:
    # POSIX signals are not implemented natively in Windows, but emulated from the C runtime.
    # As consumed by CPython, most of handlers on theses signals are useless, in particular
    # SIGTERM: for instance, os.kill(pid, signal.SIGTERM) will call TerminateProcess, that stops
    # immediately the process without calling the attached handler. Besides, non-POSIX signals
    # (CTRL_C_EVENT and CTRL_BREAK_EVENT) are implemented in a console context to handle the
    # CTRL+C event to a process launched from the console. Only CTRL_C_EVENT has a reliable
    # behavior in fact, and maps to the handler to SIGINT. However in this case, a
    # KeyboardInterrupt is raised, that will be handled by ErrorHandler through the context manager
    # protocol. Finally, no signal on Windows is electable to be handled using ErrorHandler.
    #
    # Refs: https://stackoverflow.com/a/35792192, https://maruel.ca/post/python_windows_signal,
    # https://docs.python.org/2/library/os.html#os.kill,
    # https://www.reddit.com/r/Python/comments/1dsblt/windows_command_line_automation_ctrlc_question
    _SIGNALS = []


class ErrorHandler:
    """Context manager for running code that must be cleaned up on failure.

    The context manager allows you to register functions that will be called
    when an exception (excluding SystemExit) or signal is encountered.
    Usage::

        handler = ErrorHandler(cleanup1_func, *cleanup1_args, **cleanup1_kwargs)
        handler.register(cleanup2_func, *cleanup2_args, **cleanup2_kwargs)

        with handler:
            do_something()

    Or for one cleanup function::

        with ErrorHandler(func, args, kwargs):
            do_something()

    If an exception is raised out of do_something, the cleanup functions will
    be called in last in first out order. Then the exception is raised.
    Similarly, if a signal is encountered, the cleanup functions are called
    followed by the previously received signal handler.

    Each registered cleanup function is called exactly once. If a registered
    function raises an exception, it is logged and the next function is called.
    Signals received while the registered functions are executing are
    deferred until they finish.

    """
    def __init__(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        self.call_on_regular_exit = False
        self.body_executed = False
        self.funcs: List[Callable[[], Any]] = []
        self.prev_handlers: Dict[int, Union[int, None, Callable]] = {}
        self.received_signals: List[int] = []
        if func is not None:
            self.register(func, *args, **kwargs)

    def __enter__(self) -> None:
        self.body_executed = False
        self._set_signal_handlers()

    def __exit__(self, exec_type: Optional[Type[BaseException]],
                 exec_value: Optional[BaseException],
                 trace: Optional[TracebackType]) -> bool:
        self.body_executed = True
        retval = False
        # SystemExit is ignored to properly handle forks that don't exec
        if exec_type is SystemExit:
            return retval
        if exec_type is None:
            if not self.call_on_regular_exit:
                return retval
        elif exec_type is errors.SignalExit:
            logger.debug("Encountered signals: %s", self.received_signals)
            retval = True
        else:
            logger.debug("Encountered exception:\n%s", "".join(
                traceback.format_exception(exec_type, exec_value, trace)))

        self._call_registered()
        self._reset_signal_handlers()
        self._call_signals()
        return retval

    def register(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        """Sets func to be run with the given arguments during cleanup.

        :param function func: function to be called in case of an error

        """
        self.funcs.append(functools.partial(func, *args, **kwargs))

    def _call_registered(self) -> None:
        """Calls all registered functions"""
        logger.debug("Calling registered functions")
        while self.funcs:
            try:
                self.funcs[-1]()
            except Exception as exc:  # pylint: disable=broad-except
                output = traceback.format_exception_only(type(exc), exc)
                logger.error("Encountered exception during recovery: %s",
                             ''.join(output).rstrip())
            self.funcs.pop()

    def _set_signal_handlers(self) -> None:
        """Sets signal handlers for signals in _SIGNALS."""
        for signum in _SIGNALS:
            prev_handler = signal.getsignal(signum)
            # If prev_handler is None, the handler was set outside of Python
            if prev_handler is not None:
                self.prev_handlers[signum] = prev_handler
                signal.signal(signum, self._signal_handler)

    def _reset_signal_handlers(self) -> None:
        """Resets signal handlers for signals in _SIGNALS."""
        for signum, handler in self.prev_handlers.items():
            signal.signal(signum, handler)
        self.prev_handlers.clear()

    def _signal_handler(self, signum: int, unused_frame: Any) -> None:
        """Replacement function for handling received signals.

        Store the received signal. If we are executing the code block in
        the body of the context manager, stop by raising signal exit.

        :param int signum: number of current signal

        """
        self.received_signals.append(signum)
        if not self.body_executed:
            raise errors.SignalExit

    def _call_signals(self) -> None:
        """Finally call the deferred signals."""
        for signum in self.received_signals:
            logger.debug("Calling signal %s", signum)
            os.kill(os.getpid(), signum)


class ExitHandler(ErrorHandler):
    """Context manager for running code that must be cleaned up.

    Subclass of ErrorHandler, with the same usage and parameters.
    In addition to cleaning up on all signals, also cleans up on
    regular exit.
    """
    def __init__(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__(func, *args, **kwargs)
        self.call_on_regular_exit = True
