# Stubs for fcntl
from io import IOBase
from typing import Any, IO, Union

FASYNC: int
FD_CLOEXEC: int
DN_ACCESS: int
DN_ATTRIB: int
DN_CREATE: int
DN_DELETE: int
DN_MODIFY: int
DN_MULTISHOT: int
DN_RENAME: int
F_DUPFD: int
F_DUPFD_CLOEXEC: int
F_FULLFSYNC: int
F_EXLCK: int
F_GETFD: int
F_GETFL: int
F_GETLEASE: int
F_GETLK: int
F_GETLK64: int
F_GETOWN: int
F_NOCACHE: int
F_GETSIG: int
F_NOTIFY: int
F_RDLCK: int
F_SETFD: int
F_SETFL: int
F_SETLEASE: int
F_SETLK: int
F_SETLK64: int
F_SETLKW: int
F_SETLKW64: int
F_SETOWN: int
F_SETSIG: int
F_SHLCK: int
F_UNLCK: int
F_WRLCK: int
I_ATMARK: int
I_CANPUT: int
I_CKBAND: int
I_FDINSERT: int
I_FIND: int
I_FLUSH: int
I_FLUSHBAND: int
I_GETBAND: int
I_GETCLTIME: int
I_GETSIG: int
I_GRDOPT: int
I_GWROPT: int
I_LINK: int
I_LIST: int
I_LOOK: int
I_NREAD: int
I_PEEK: int
I_PLINK: int
I_POP: int
I_PUNLINK: int
I_PUSH: int
I_RECVFD: int
I_SENDFD: int
I_SETCLTIME: int
I_SETSIG: int
I_SRDOPT: int
I_STR: int
I_SWROPT: int
I_UNLINK: int
LOCK_EX: int
LOCK_MAND: int
LOCK_NB: int
LOCK_READ: int
LOCK_RW: int
LOCK_SH: int
LOCK_UN: int
LOCK_WRITE: int

_AnyFile = Union[int, IO[Any], IOBase]

# TODO All these return either int or bytes depending on the value of
# cmd (not on the type of arg).
def fcntl(fd: _AnyFile,
          cmd: int,
          arg: Union[int, bytes] = ...) -> Any: ...
# TODO This function accepts any object supporting a buffer interface,
# as arg, is there a better way to express this than bytes?
def ioctl(fd: _AnyFile,
          request: int,
          arg: Union[int, bytes] = ...,
          mutate_flag: bool = ...) -> Any: ...
def flock(fd: _AnyFile, operation: int) -> None: ...
def lockf(fd: _AnyFile,
          cmd: int,
          len: int = ...,
          start: int = ...,
          whence: int = ...) -> Any: ...
