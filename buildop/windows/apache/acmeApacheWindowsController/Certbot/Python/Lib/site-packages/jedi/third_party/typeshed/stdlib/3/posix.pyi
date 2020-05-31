# Stubs for posix

# NOTE: These are incomplete!

import sys
from typing import List, NamedTuple, Optional, overload

from os import stat_result as stat_result

if sys.version_info >= (3, 6):
    from builtins import _PathLike  # See comment in builtins

class uname_result(NamedTuple):
    sysname: str
    nodename: str
    release: str
    version: str
    machine: str

class times_result(NamedTuple):
    user: float
    system: float
    children_user: float
    children_system: float
    elapsed: float

class waitid_result(NamedTuple):
    si_pid: int
    si_uid: int
    si_signo: int
    si_status: int
    si_code: int

class sched_param(NamedTuple):
    sched_priority: int

EX_CANTCREAT: int
EX_CONFIG: int
EX_DATAERR: int
EX_IOERR: int
EX_NOHOST: int
EX_NOINPUT: int
EX_NOPERM: int
EX_NOTFOUND: int
EX_NOUSER: int
EX_OK: int
EX_OSERR: int
EX_OSFILE: int
EX_PROTOCOL: int
EX_SOFTWARE: int
EX_TEMPFAIL: int
EX_UNAVAILABLE: int
EX_USAGE: int

F_OK: int
R_OK: int
W_OK: int
X_OK: int

if sys.version_info >= (3, 6):
    GRND_NONBLOCK: int
    GRND_RANDOM: int
NGROUPS_MAX: int

O_APPEND: int
O_ACCMODE: int
O_ASYNC: int
O_CREAT: int
O_DIRECT: int
O_DIRECTORY: int
O_DSYNC: int
O_EXCL: int
O_LARGEFILE: int
O_NDELAY: int
O_NOATIME: int
O_NOCTTY: int
O_NOFOLLOW: int
O_NONBLOCK: int
O_RDONLY: int
O_RDWR: int
O_RSYNC: int
O_SYNC: int
O_TRUNC: int
O_WRONLY: int

ST_APPEND: int
ST_MANDLOCK: int
ST_NOATIME: int
ST_NODEV: int
ST_NODIRATIME: int
ST_NOEXEC: int
ST_NOSUID: int
ST_RDONLY: int
ST_RELATIME: int
ST_SYNCHRONOUS: int
ST_WRITE: int

TMP_MAX: int
WCONTINUED: int
WCOREDUMP: int
WEXITSTATUS: int
WIFCONTINUED: int
WIFEXITED: int
WIFSIGNALED: int
WIFSTOPPED: int
WNOHANG: int
WSTOPSIG: int
WTERMSIG: int
WUNTRACED: int

if sys.version_info >= (3, 6):
    @overload
    def listdir(path: Optional[str] = ...) -> List[str]: ...
    @overload
    def listdir(path: bytes) -> List[bytes]: ...
    @overload
    def listdir(path: int) -> List[str]: ...
    @overload
    def listdir(path: _PathLike[str]) -> List[str]: ...
else:
    @overload
    def listdir(path: Optional[str] = ...) -> List[str]: ...
    @overload
    def listdir(path: bytes) -> List[bytes]: ...
    @overload
    def listdir(path: int) -> List[str]: ...
