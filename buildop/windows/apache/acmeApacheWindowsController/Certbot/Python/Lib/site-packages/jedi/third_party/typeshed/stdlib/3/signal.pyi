"""Stub file for the 'signal' module."""

from enum import IntEnum
from typing import Any, Callable, Tuple, Union, Optional, Iterable, Set
from types import FrameType

class ItimerError(IOError): ...

ITIMER_PROF: int
ITIMER_REAL: int
ITIMER_VIRTUAL: int

NSIG: int

class Signals(IntEnum):
    SIGABRT: int
    SIGALRM: int
    SIGBREAK: int  # Windows
    SIGBUS: int
    SIGCHLD: int
    SIGCLD: int
    SIGCONT: int
    SIGEMT: int
    SIGFPE: int
    SIGHUP: int
    SIGILL: int
    SIGINFO: int
    SIGINT: int
    SIGIO: int
    SIGIOT: int
    SIGKILL: int
    SIGPIPE: int
    SIGPOLL: int
    SIGPROF: int
    SIGPWR: int
    SIGQUIT: int
    SIGRTMAX: int
    SIGRTMIN: int
    SIGSEGV: int
    SIGSTOP: int
    SIGSYS: int
    SIGTERM: int
    SIGTRAP: int
    SIGTSTP: int
    SIGTTIN: int
    SIGTTOU: int
    SIGURG: int
    SIGUSR1: int
    SIGUSR2: int
    SIGVTALRM: int
    SIGWINCH: int
    SIGXCPU: int
    SIGXFSZ: int

class Handlers(IntEnum):
    SIG_DFL: int
    SIG_IGN: int

SIG_DFL = Handlers.SIG_DFL
SIG_IGN = Handlers.SIG_IGN

class Sigmasks(IntEnum):
    SIG_BLOCK: int
    SIG_UNBLOCK: int
    SIG_SETMASK: int

SIG_BLOCK = Sigmasks.SIG_BLOCK
SIG_UNBLOCK = Sigmasks.SIG_UNBLOCK
SIG_SETMASK = Sigmasks.SIG_SETMASK

_SIGNUM = Union[int, Signals]
_HANDLER = Union[Callable[[Signals, FrameType], None], int, Handlers, None]

SIGABRT: Signals
SIGALRM: Signals
SIGBREAK: Signals  # Windows
SIGBUS: Signals
SIGCHLD: Signals
SIGCLD: Signals
SIGCONT: Signals
SIGEMT: Signals
SIGFPE: Signals
SIGHUP: Signals
SIGILL: Signals
SIGINFO: Signals
SIGINT: Signals
SIGIO: Signals
SIGIOT: Signals
SIGKILL: Signals
SIGPIPE: Signals
SIGPOLL: Signals
SIGPROF: Signals
SIGPWR: Signals
SIGQUIT: Signals
SIGRTMAX: Signals
SIGRTMIN: Signals
SIGSEGV: Signals
SIGSTOP: Signals
SIGSYS: Signals
SIGTERM: Signals
SIGTRAP: Signals
SIGTSTP: Signals
SIGTTIN: Signals
SIGTTOU: Signals
SIGURG: Signals
SIGUSR1: Signals
SIGUSR2: Signals
SIGVTALRM: Signals
SIGWINCH: Signals
SIGXCPU: Signals
SIGXFSZ: Signals

# Windows
CTRL_C_EVENT: int
CTRL_BREAK_EVENT: int

class struct_siginfo(Tuple[int, int, int, int, int, int, int]):
    def __init__(self, sequence: Iterable[int]) -> None: ...
    @property
    def si_signo(self) -> int: ...
    @property
    def si_code(self) -> int: ...
    @property
    def si_errno(self) -> int: ...
    @property
    def si_pid(self) -> int: ...
    @property
    def si_uid(self) -> int: ...
    @property
    def si_status(self) -> int: ...
    @property
    def si_band(self) -> int: ...

def alarm(time: int) -> int: ...
def default_int_handler(signum: int, frame: FrameType) -> None: ...
def getitimer(which: int) -> Tuple[float, float]: ...
def getsignal(signalnum: _SIGNUM) -> _HANDLER: ...
def pause() -> None: ...
def pthread_kill(thread_id: int, signum: int) -> None: ...
def pthread_sigmask(how: int, mask: Iterable[int]) -> Set[_SIGNUM]: ...
def set_wakeup_fd(fd: int) -> int: ...
def setitimer(which: int, seconds: float, interval: float = ...) -> Tuple[float, float]: ...
def siginterrupt(signalnum: int, flag: bool) -> None: ...
def signal(signalnum: _SIGNUM, handler: _HANDLER) -> _HANDLER: ...
def sigpending() -> Any: ...
def sigtimedwait(sigset: Iterable[int], timeout: float) -> Optional[struct_siginfo]: ...
def sigwait(sigset: Iterable[int]) -> _SIGNUM: ...
def sigwaitinfo(sigset: Iterable[int]) -> struct_siginfo: ...
