# Stubs for os
# Ron Murawski <ron@horizonchess.com>

from io import TextIOWrapper as _TextIOWrapper
from posix import listdir as listdir, times_result
import sys
from typing import (
    Mapping, MutableMapping, Dict, List, Any, Tuple, Iterable, Iterator, NoReturn, overload, Union, AnyStr,
    Optional, Generic, Set, Callable, Text, Sequence, NamedTuple, TypeVar, ContextManager
)

# Re-exported names from other modules.
from builtins import OSError as error
from . import path as path

_T = TypeVar('_T')

# ----- os variables -----

supports_bytes_environ: bool

supports_dir_fd: Set[Callable[..., Any]]
supports_fd: Set[Callable[..., Any]]
supports_effective_ids: Set[Callable[..., Any]]
supports_follow_symlinks: Set[Callable[..., Any]]

if sys.platform != 'win32':
    # Unix only
    PRIO_PROCESS: int
    PRIO_PGRP: int
    PRIO_USER: int

    F_LOCK: int
    F_TLOCK: int
    F_ULOCK: int
    F_TEST: int

    POSIX_FADV_NORMAL: int
    POSIX_FADV_SEQUENTIAL: int
    POSIX_FADV_RANDOM: int
    POSIX_FADV_NOREUSE: int
    POSIX_FADV_WILLNEED: int
    POSIX_FADV_DONTNEED: int

    SF_NODISKIO: int
    SF_MNOWAIT: int
    SF_SYNC: int

    XATTR_SIZE_MAX: int  # Linux only
    XATTR_CREATE: int  # Linux only
    XATTR_REPLACE: int  # Linux only

    P_PID: int
    P_PGID: int
    P_ALL: int

    WEXITED: int
    WSTOPPED: int
    WNOWAIT: int

    CLD_EXITED: int
    CLD_DUMPED: int
    CLD_TRAPPED: int
    CLD_CONTINUED: int

    SCHED_OTHER: int  # some flavors of Unix
    SCHED_BATCH: int  # some flavors of Unix
    SCHED_IDLE: int  # some flavors of Unix
    SCHED_SPORADIC: int  # some flavors of Unix
    SCHED_FIFO: int  # some flavors of Unix
    SCHED_RR: int  # some flavors of Unix
    SCHED_RESET_ON_FORK: int  # some flavors of Unix

RTLD_LAZY: int
RTLD_NOW: int
RTLD_GLOBAL: int
RTLD_LOCAL: int
RTLD_NODELETE: int
RTLD_NOLOAD: int
RTLD_DEEPBIND: int

SEEK_SET: int
SEEK_CUR: int
SEEK_END: int
if sys.platform != 'win32':
    SEEK_DATA: int  # some flavors of Unix
    SEEK_HOLE: int  # some flavors of Unix

O_RDONLY: int
O_WRONLY: int
O_RDWR: int
O_APPEND: int
O_CREAT: int
O_EXCL: int
O_TRUNC: int
# We don't use sys.platform for O_* flags to denote platform-dependent APIs because some codes,
# including tests for mypy, use a more finer way than sys.platform before using these APIs
# See https://github.com/python/typeshed/pull/2286 for discussions
O_DSYNC: int    # Unix only
O_RSYNC: int    # Unix only
O_SYNC: int     # Unix only
O_NDELAY: int   # Unix only
O_NONBLOCK: int  # Unix only
O_NOCTTY: int   # Unix only
O_CLOEXEC: int  # Unix only
O_SHLOCK: int   # Unix only
O_EXLOCK: int   # Unix only
O_BINARY: int     # Windows only
O_NOINHERIT: int  # Windows only
O_SHORT_LIVED: int  # Windows only
O_TEMPORARY: int  # Windows only
O_RANDOM: int     # Windows only
O_SEQUENTIAL: int  # Windows only
O_TEXT: int       # Windows only
O_ASYNC: int      # Gnu extension if in C library
O_DIRECT: int     # Gnu extension if in C library
O_DIRECTORY: int  # Gnu extension if in C library
O_NOFOLLOW: int   # Gnu extension if in C library
O_NOATIME: int    # Gnu extension if in C library
O_PATH: int  # Gnu extension if in C library
O_TMPFILE: int  # Gnu extension if in C library
O_LARGEFILE: int  # Gnu extension if in C library

curdir: str
pardir: str
sep: str
if sys.platform == 'win32':
    altsep: str
else:
    altsep: Optional[str]
extsep: str
pathsep: str
defpath: str
linesep: str
devnull: str
name: str

F_OK: int
R_OK: int
W_OK: int
X_OK: int

class _Environ(MutableMapping[AnyStr, AnyStr], Generic[AnyStr]):
    def copy(self) -> Dict[AnyStr, AnyStr]: ...
    def __delitem__(self, key: AnyStr) -> None: ...
    def __getitem__(self, key: AnyStr) -> AnyStr: ...
    def __setitem__(self, key: AnyStr, value: AnyStr) -> None: ...
    def __iter__(self) -> Iterator[AnyStr]: ...
    def __len__(self) -> int: ...

environ: _Environ[str]
environb: _Environ[bytes]

if sys.platform != 'win32':
    confstr_names: Dict[str, int]
    pathconf_names: Dict[str, int]
    sysconf_names: Dict[str, int]

    EX_OK: int
    EX_USAGE: int
    EX_DATAERR: int
    EX_NOINPUT: int
    EX_NOUSER: int
    EX_NOHOST: int
    EX_UNAVAILABLE: int
    EX_SOFTWARE: int
    EX_OSERR: int
    EX_OSFILE: int
    EX_CANTCREAT: int
    EX_IOERR: int
    EX_TEMPFAIL: int
    EX_PROTOCOL: int
    EX_NOPERM: int
    EX_CONFIG: int
    EX_NOTFOUND: int

P_NOWAIT: int
P_NOWAITO: int
P_WAIT: int
if sys.platform == 'win32':
    P_DETACH: int
    P_OVERLAY: int

# wait()/waitpid() options
if sys.platform != 'win32':
    WNOHANG: int  # Unix only
    WCONTINUED: int  # some Unix systems
    WUNTRACED: int  # Unix only

TMP_MAX: int  # Undocumented, but used by tempfile

# ----- os classes (structures) -----
class stat_result:
    # For backward compatibility, the return value of stat() is also
    # accessible as a tuple of at least 10 integers giving the most important
    # (and portable) members of the stat structure, in the order st_mode,
    # st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, st_atime, st_mtime,
    # st_ctime. More items may be added at the end by some implementations.

    st_mode: int  # protection bits,
    st_ino: int  # inode number,
    st_dev: int  # device,
    st_nlink: int  # number of hard links,
    st_uid: int  # user id of owner,
    st_gid: int  # group id of owner,
    st_size: int  # size of file, in bytes,
    st_atime: float  # time of most recent access,
    st_mtime: float  # time of most recent content modification,
    st_ctime: float  # platform dependent (time of most recent metadata change on Unix, or the time of creation on Windows)
    st_atime_ns: int  # time of most recent access, in nanoseconds
    st_mtime_ns: int  # time of most recent content modification in nanoseconds
    st_ctime_ns: int  # platform dependent (time of most recent metadata change on Unix, or the time of creation on Windows) in nanoseconds
    if sys.version_info >= (3, 8) and sys.platform == "win32":
        st_reparse_tag: int

    def __getitem__(self, i: int) -> int: ...

    # not documented
    def __init__(self, tuple: Tuple[int, ...]) -> None: ...

    # On some Unix systems (such as Linux), the following attributes may also
    # be available:
    st_blocks: int  # number of blocks allocated for file
    st_blksize: int  # filesystem blocksize
    st_rdev: int  # type of device if an inode device
    st_flags: int  # user defined flags for file

    # On other Unix systems (such as FreeBSD), the following attributes may be
    # available (but may be only filled out if root tries to use them):
    st_gen: int  # file generation number
    st_birthtime: int  # time of file creation

    # On Mac OS systems, the following attributes may also be available:
    st_rsize: int
    st_creator: int
    st_type: int

if sys.version_info >= (3, 6):
    from builtins import _PathLike as PathLike  # See comment in builtins

_PathType = path._PathType
_FdOrPathType = Union[int, _PathType]

if sys.version_info >= (3, 6):
    class DirEntry(PathLike[AnyStr]):
        # This is what the scandir interator yields
        # The constructor is hidden

        name: AnyStr
        path: AnyStr
        def inode(self) -> int: ...
        def is_dir(self, *, follow_symlinks: bool = ...) -> bool: ...
        def is_file(self, *, follow_symlinks: bool = ...) -> bool: ...
        def is_symlink(self) -> bool: ...
        def stat(self, *, follow_symlinks: bool = ...) -> stat_result: ...

        def __fspath__(self) -> AnyStr: ...
else:
    class DirEntry(Generic[AnyStr]):
        # This is what the scandir interator yields
        # The constructor is hidden

        name: AnyStr
        path: AnyStr
        def inode(self) -> int: ...
        def is_dir(self, *, follow_symlinks: bool = ...) -> bool: ...
        def is_file(self, *, follow_symlinks: bool = ...) -> bool: ...
        def is_symlink(self) -> bool: ...
        def stat(self, *, follow_symlinks: bool = ...) -> stat_result: ...


if sys.platform != 'win32':
    class statvfs_result:  # Unix only
        f_bsize: int
        f_frsize: int
        f_blocks: int
        f_bfree: int
        f_bavail: int
        f_files: int
        f_ffree: int
        f_favail: int
        f_flag: int
        f_namemax: int

# ----- os function stubs -----
if sys.version_info >= (3, 6):
    def fsencode(filename: Union[str, bytes, PathLike[Any]]) -> bytes: ...
else:
    def fsencode(filename: Union[str, bytes]) -> bytes: ...

if sys.version_info >= (3, 6):
    def fsdecode(filename: Union[str, bytes, PathLike[Any]]) -> str: ...
else:
    def fsdecode(filename: Union[str, bytes]) -> str: ...

if sys.version_info >= (3, 6):
    @overload
    def fspath(path: str) -> str: ...
    @overload
    def fspath(path: bytes) -> bytes: ...
    @overload
    def fspath(path: PathLike[Any]) -> Any: ...

def get_exec_path(env: Optional[Mapping[str, str]] = ...) -> List[str]: ...
# NOTE: get_exec_path(): returns List[bytes] when env not None
def getlogin() -> str: ...
def getpid() -> int: ...
def getppid() -> int: ...
def strerror(code: int) -> str: ...
def umask(mask: int) -> int: ...

if sys.platform != 'win32':
    # Unix only
    def ctermid() -> str: ...
    def getegid() -> int: ...
    def geteuid() -> int: ...
    def getgid() -> int: ...
    def getgrouplist(user: str, gid: int) -> List[int]: ...
    def getgroups() -> List[int]: ...  # Unix only, behaves differently on Mac
    def initgroups(username: str, gid: int) -> None: ...
    def getpgid(pid: int) -> int: ...
    def getpgrp() -> int: ...
    def getpriority(which: int, who: int) -> int: ...
    def setpriority(which: int, who: int, priority: int) -> None: ...
    def getresuid() -> Tuple[int, int, int]: ...
    def getresgid() -> Tuple[int, int, int]: ...
    def getuid() -> int: ...
    def setegid(egid: int) -> None: ...
    def seteuid(euid: int) -> None: ...
    def setgid(gid: int) -> None: ...
    def setgroups(groups: Sequence[int]) -> None: ...
    def setpgrp() -> None: ...
    def setpgid(pid: int, pgrp: int) -> None: ...
    def setregid(rgid: int, egid: int) -> None: ...
    def setresgid(rgid: int, egid: int, sgid: int) -> None: ...
    def setresuid(ruid: int, euid: int, suid: int) -> None: ...
    def setreuid(ruid: int, euid: int) -> None: ...
    def getsid(pid: int) -> int: ...
    def setsid() -> None: ...
    def setuid(uid: int) -> None: ...
    from posix import uname_result
    def uname() -> uname_result: ...

@overload
def getenv(key: Text) -> Optional[str]: ...
@overload
def getenv(key: Text, default: _T) -> Union[str, _T]: ...
def getenvb(key: bytes, default: bytes = ...) -> bytes: ...
def putenv(key: Union[bytes, Text], value: Union[bytes, Text]) -> None: ...
def unsetenv(key: Union[bytes, Text]) -> None: ...

# Return IO or TextIO
def fdopen(fd: int, mode: str = ..., buffering: int = ..., encoding: Optional[str] = ...,
           errors: str = ..., newline: str = ..., closefd: bool = ...) -> Any: ...
def close(fd: int) -> None: ...
def closerange(fd_low: int, fd_high: int) -> None: ...
def device_encoding(fd: int) -> Optional[str]: ...
def dup(fd: int) -> int: ...
if sys.version_info >= (3, 7):
    def dup2(fd: int, fd2: int, inheritable: bool = ...) -> int: ...
else:
    def dup2(fd: int, fd2: int, inheritable: bool = ...) -> None: ...
def fstat(fd: int) -> stat_result: ...
def fsync(fd: int) -> None: ...
def lseek(fd: int, pos: int, how: int) -> int: ...
def open(file: _PathType, flags: int, mode: int = ..., *, dir_fd: Optional[int] = ...) -> int: ...
def pipe() -> Tuple[int, int]: ...
def read(fd: int, n: int) -> bytes: ...

if sys.platform != 'win32':
    # Unix only
    def fchmod(fd: int, mode: int) -> None: ...
    def fchown(fd: int, uid: int, gid: int) -> None: ...
    def fdatasync(fd: int) -> None: ...  # Unix only, not Mac
    def fpathconf(fd: int, name: Union[str, int]) -> int: ...
    def fstatvfs(fd: int) -> statvfs_result: ...
    def ftruncate(fd: int, length: int) -> None: ...
    def get_blocking(fd: int) -> bool: ...
    def set_blocking(fd: int, blocking: bool) -> None: ...
    def isatty(fd: int) -> bool: ...
    def lockf(__fd: int, __cmd: int, __length: int) -> None: ...
    def openpty() -> Tuple[int, int]: ...  # some flavors of Unix
    def pipe2(flags: int) -> Tuple[int, int]: ...  # some flavors of Unix
    def posix_fallocate(fd: int, offset: int, length: int) -> None: ...
    def posix_fadvise(fd: int, offset: int, length: int, advice: int) -> None: ...
    def pread(fd: int, buffersize: int, offset: int) -> bytes: ...
    def pwrite(fd: int, string: bytes, offset: int) -> int: ...
    @overload
    def sendfile(__out_fd: int, __in_fd: int, offset: Optional[int], count: int) -> int: ...
    @overload
    def sendfile(__out_fd: int, __in_fd: int, offset: int, count: int,
                 headers: Sequence[bytes] = ..., trailers: Sequence[bytes] = ..., flags: int = ...) -> int: ...  # FreeBSD and Mac OS X only
    def readv(fd: int, buffers: Sequence[bytearray]) -> int: ...
    def writev(fd: int, buffers: Sequence[bytes]) -> int: ...

class terminal_size(Tuple[int, int]):
    columns: int
    lines: int
def get_terminal_size(fd: int = ...) -> terminal_size: ...

def get_inheritable(fd: int) -> bool: ...
def set_inheritable(fd: int, inheritable: bool) -> None: ...

if sys.platform != 'win32':
    # Unix only
    def tcgetpgrp(fd: int) -> int: ...
    def tcsetpgrp(fd: int, pg: int) -> None: ...
    def ttyname(fd: int) -> str: ...
def write(fd: int, string: bytes) -> int: ...
def access(
    path: _FdOrPathType,
    mode: int,
    *,
    dir_fd: Optional[int] = ...,
    effective_ids: bool = ...,
    follow_symlinks: bool = ...,
) -> bool: ...
def chdir(path: _FdOrPathType) -> None: ...
def fchdir(fd: int) -> None: ...
def getcwd() -> str: ...
def getcwdb() -> bytes: ...
def chmod(path: _FdOrPathType, mode: int, *, dir_fd: Optional[int] = ..., follow_symlinks: bool = ...) -> None: ...
if sys.platform != 'win32':
    def chflags(path: _PathType, flags: int, follow_symlinks: bool = ...) -> None: ...  # some flavors of Unix
    def chown(path: _FdOrPathType, uid: int, gid: int, *, dir_fd: Optional[int] = ..., follow_symlinks: bool = ...) -> None: ...  # Unix only
if sys.platform != 'win32':
    # Unix only
    def chroot(path: _PathType) -> None: ...
    def lchflags(path: _PathType, flags: int) -> None: ...
    def lchmod(path: _PathType, mode: int) -> None: ...
    def lchown(path: _PathType, uid: int, gid: int) -> None: ...
def link(
    src: _PathType,
    link_name: _PathType,
    *,
    src_dir_fd: Optional[int] = ...,
    dst_dir_fd: Optional[int] = ...,
    follow_symlinks: bool = ...,
) -> None: ...

def lstat(path: _PathType, *, dir_fd: Optional[int] = ...) -> stat_result: ...
def mkdir(path: _PathType, mode: int = ..., *, dir_fd: Optional[int] = ...) -> None: ...
if sys.platform != 'win32':
    def mkfifo(path: _PathType, mode: int = ..., *, dir_fd: Optional[int] = ...) -> None: ...  # Unix only
def makedirs(name: _PathType, mode: int = ..., exist_ok: bool = ...) -> None: ...
def mknod(path: _PathType, mode: int = ..., device: int = ..., *, dir_fd: Optional[int] = ...) -> None: ...
def major(device: int) -> int: ...
def minor(device: int) -> int: ...
def makedev(major: int, minor: int) -> int: ...
if sys.platform != 'win32':
    def pathconf(path: _FdOrPathType, name: Union[str, int]) -> int: ...  # Unix only
if sys.version_info >= (3, 6):
    def readlink(path: Union[AnyStr, PathLike[AnyStr]], *, dir_fd: Optional[int] = ...) -> AnyStr: ...
else:
    def readlink(path: AnyStr, *, dir_fd: Optional[int] = ...) -> AnyStr: ...
def remove(path: _PathType, *, dir_fd: Optional[int] = ...) -> None: ...
def removedirs(name: _PathType) -> None: ...
def rename(src: _PathType, dst: _PathType, *, src_dir_fd: Optional[int] = ..., dst_dir_fd: Optional[int] = ...) -> None: ...
def renames(old: _PathType, new: _PathType) -> None: ...
def replace(src: _PathType, dst: _PathType, *, src_dir_fd: Optional[int] = ..., dst_dir_fd: Optional[int] = ...) -> None: ...
def rmdir(path: _PathType, *, dir_fd: Optional[int] = ...) -> None: ...
if sys.version_info >= (3, 7):
    class _ScandirIterator(Iterator[DirEntry[AnyStr]], ContextManager[_ScandirIterator[AnyStr]]):
        def __next__(self) -> DirEntry[AnyStr]: ...
        def close(self) -> None: ...
    @overload
    def scandir() -> _ScandirIterator[str]: ...
    @overload
    def scandir(path: int) -> _ScandirIterator[str]: ...
    @overload
    def scandir(path: Union[AnyStr, PathLike[AnyStr]]) -> _ScandirIterator[AnyStr]: ...
elif sys.version_info >= (3, 6):
    class _ScandirIterator(Iterator[DirEntry[AnyStr]], ContextManager[_ScandirIterator[AnyStr]]):
        def __next__(self) -> DirEntry[AnyStr]: ...
        def close(self) -> None: ...
    @overload
    def scandir() -> _ScandirIterator[str]: ...
    @overload
    def scandir(path: Union[AnyStr, PathLike[AnyStr]]) -> _ScandirIterator[AnyStr]: ...
else:
    @overload
    def scandir() -> Iterator[DirEntry[str]]: ...
    @overload
    def scandir(path: AnyStr) -> Iterator[DirEntry[AnyStr]]: ...
def stat(path: _FdOrPathType, *, dir_fd: Optional[int] = ..., follow_symlinks: bool = ...) -> stat_result: ...
if sys.version_info < (3, 7):
    @overload
    def stat_float_times() -> bool: ...
    @overload
    def stat_float_times(__newvalue: bool) -> None: ...
if sys.platform != 'win32':
    def statvfs(path: _FdOrPathType) -> statvfs_result: ...  # Unix only
def symlink(
    source: _PathType,
    link_name: _PathType,
    target_is_directory: bool = ...,
    *,
    dir_fd: Optional[int] = ...,
) -> None: ...
if sys.platform != 'win32':
    def sync() -> None: ...  # Unix only
def truncate(path: _FdOrPathType, length: int) -> None: ...  # Unix only up to version 3.4
def unlink(path: _PathType, *, dir_fd: Optional[int] = ...) -> None: ...
def utime(
    path: _FdOrPathType,
    times: Optional[Union[Tuple[int, int], Tuple[float, float]]] = ...,
    *,
    ns: Tuple[int, int] = ...,
    dir_fd: Optional[int] = ...,
    follow_symlinks: bool = ...,
) -> None: ...

_OnError = Callable[[OSError], Any]

if sys.version_info >= (3, 6):
    def walk(top: Union[AnyStr, PathLike[AnyStr]], topdown: bool = ...,
             onerror: Optional[_OnError] = ...,
             followlinks: bool = ...) -> Iterator[Tuple[AnyStr, List[AnyStr],
                                                        List[AnyStr]]]: ...
else:
    def walk(top: AnyStr, topdown: bool = ..., onerror: Optional[_OnError] = ...,
             followlinks: bool = ...) -> Iterator[Tuple[AnyStr, List[AnyStr],
                                                        List[AnyStr]]]: ...
if sys.platform != 'win32':
    if sys.version_info >= (3, 7):
        @overload
        def fwalk(top: Union[str, PathLike[str]] = ..., topdown: bool = ...,
                  onerror: Optional[_OnError] = ..., *, follow_symlinks: bool = ...,
                  dir_fd: Optional[int] = ...) -> Iterator[Tuple[str, List[str], List[str], int]]: ...
        @overload
        def fwalk(top: bytes, topdown: bool = ...,
                  onerror: Optional[_OnError] = ..., *, follow_symlinks: bool = ...,
                  dir_fd: Optional[int] = ...) -> Iterator[Tuple[bytes, List[bytes], List[bytes], int]]: ...
    elif sys.version_info >= (3, 6):
        def fwalk(top: Union[str, PathLike[str]] = ..., topdown: bool = ...,
                  onerror: Optional[_OnError] = ..., *, follow_symlinks: bool = ...,
                  dir_fd: Optional[int] = ...) -> Iterator[Tuple[str, List[str], List[str], int]]: ...
    else:
        def fwalk(top: str = ..., topdown: bool = ...,
                  onerror: Optional[_OnError] = ..., *, follow_symlinks: bool = ...,
                  dir_fd: Optional[int] = ...) -> Iterator[Tuple[str, List[str], List[str], int]]: ...
    def getxattr(path: _FdOrPathType, attribute: _PathType, *, follow_symlinks: bool = ...) -> bytes: ...  # Linux only
    def listxattr(path: _FdOrPathType, *, follow_symlinks: bool = ...) -> List[str]: ...  # Linux only
    def removexattr(path: _FdOrPathType, attribute: _PathType, *, follow_symlinks: bool = ...) -> None: ...  # Linux only
    def setxattr(path: _FdOrPathType, attribute: _PathType, value: bytes, flags: int = ..., *,
                 follow_symlinks: bool = ...) -> None: ...  # Linux only

def abort() -> NoReturn: ...
# These are defined as execl(file, *args) but the first *arg is mandatory.
def execl(file: _PathType, __arg0: Union[bytes, Text], *args: Union[bytes, Text]) -> NoReturn: ...
def execlp(file: _PathType, __arg0: Union[bytes, Text], *args: Union[bytes, Text]) -> NoReturn: ...

# These are: execle(file, *args, env) but env is pulled from the last element of the args.
def execle(file: _PathType, __arg0: Union[bytes, Text], *args: Any) -> NoReturn: ...
def execlpe(file: _PathType, __arg0: Union[bytes, Text], *args: Any) -> NoReturn: ...

# The docs say `args: tuple or list of strings`
# The implementation enforces tuple or list so we can't use Sequence.
_ExecVArgs = Union[Tuple[Union[bytes, Text], ...], List[bytes], List[Text], List[Union[bytes, Text]]]
_ExecEnv = Union[Mapping[bytes, Union[bytes, str]], Mapping[str, Union[bytes, str]]]
def execv(path: _PathType, args: _ExecVArgs) -> NoReturn: ...
def execve(path: _FdOrPathType, args: _ExecVArgs, env: _ExecEnv) -> NoReturn: ...
def execvp(file: _PathType, args: _ExecVArgs) -> NoReturn: ...
def execvpe(file: _PathType, args: _ExecVArgs, env: _ExecEnv) -> NoReturn: ...

def _exit(n: int) -> NoReturn: ...
def kill(pid: int, sig: int) -> None: ...
if sys.platform != 'win32':
    # Unix only
    def fork() -> int: ...
    def forkpty() -> Tuple[int, int]: ...  # some flavors of Unix
    def killpg(pgid: int, sig: int) -> None: ...
    def nice(increment: int) -> int: ...
    def plock(op: int) -> None: ...  # ???op is int?

class _wrap_close(_TextIOWrapper):
    def close(self) -> Optional[int]: ...  # type: ignore
def popen(command: str, mode: str = ..., buffering: int = ...) -> _wrap_close: ...

def spawnl(mode: int, path: _PathType, arg0: Union[bytes, Text], *args: Union[bytes, Text]) -> int: ...
def spawnle(mode: int, path: _PathType, arg0: Union[bytes, Text],
            *args: Any) -> int: ...  # Imprecise sig
def spawnv(mode: int, path: _PathType, args: List[Union[bytes, Text]]) -> int: ...
def spawnve(mode: int, path: _PathType, args: List[Union[bytes, Text]],
            env: _ExecEnv) -> int: ...
def system(command: _PathType) -> int: ...
def times() -> times_result: ...
def waitpid(pid: int, options: int) -> Tuple[int, int]: ...

if sys.platform == 'win32':
    def startfile(path: _PathType, operation: Optional[str] = ...) -> None: ...
else:
    # Unix only
    def spawnlp(mode: int, file: _PathType, arg0: Union[bytes, Text], *args: Union[bytes, Text]) -> int: ...
    def spawnlpe(mode: int, file: _PathType, arg0: Union[bytes, Text], *args: Any) -> int: ...  # Imprecise signature
    def spawnvp(mode: int, file: _PathType, args: List[Union[bytes, Text]]) -> int: ...
    def spawnvpe(mode: int, file: _PathType, args: List[Union[bytes, Text]], env: _ExecEnv) -> int: ...
    def wait() -> Tuple[int, int]: ...  # Unix only
    from posix import waitid_result
    def waitid(idtype: int, ident: int, options: int) -> waitid_result: ...
    def wait3(options: int) -> Tuple[int, int, Any]: ...
    def wait4(pid: int, options: int) -> Tuple[int, int, Any]: ...
    def WCOREDUMP(status: int) -> bool: ...
    def WIFCONTINUED(status: int) -> bool: ...
    def WIFSTOPPED(status: int) -> bool: ...
    def WIFSIGNALED(status: int) -> bool: ...
    def WIFEXITED(status: int) -> bool: ...
    def WEXITSTATUS(status: int) -> int: ...
    def WSTOPSIG(status: int) -> int: ...
    def WTERMSIG(status: int) -> int: ...

if sys.platform != 'win32':
    from posix import sched_param
    def sched_get_priority_min(policy: int) -> int: ...  # some flavors of Unix
    def sched_get_priority_max(policy: int) -> int: ...  # some flavors of Unix
    def sched_setscheduler(pid: int, policy: int, param: sched_param) -> None: ...  # some flavors of Unix
    def sched_getscheduler(pid: int) -> int: ...  # some flavors of Unix
    def sched_setparam(pid: int, param: sched_param) -> None: ...  # some flavors of Unix
    def sched_getparam(pid: int) -> sched_param: ...  # some flavors of Unix
    def sched_rr_get_interval(pid: int) -> float: ...  # some flavors of Unix
    def sched_yield() -> None: ...  # some flavors of Unix
    def sched_setaffinity(pid: int, mask: Iterable[int]) -> None: ...  # some flavors of Unix
    def sched_getaffinity(pid: int) -> Set[int]: ...  # some flavors of Unix

def cpu_count() -> Optional[int]: ...
if sys.platform != 'win32':
    # Unix only
    def confstr(name: Union[str, int]) -> Optional[str]: ...
    def getloadavg() -> Tuple[float, float, float]: ...
    def sysconf(name: Union[str, int]) -> int: ...
if sys.version_info >= (3, 6):
    def getrandom(size: int, flags: int = ...) -> bytes: ...
    def urandom(size: int) -> bytes: ...
else:
    def urandom(n: int) -> bytes: ...

if sys.version_info >= (3, 7):
    def register_at_fork(func: Callable[..., object], when: str) -> None: ...

if sys.version_info >= (3, 8):
    if sys.platform == "win32":
        class _AddedDllDirectory:
            path: Optional[str]
            def close(self) -> None: ...
            def __enter__(self: _T) -> _T: ...
            def __exit__(self, *args: Any) -> None: ...
        def add_dll_directory(path: str) -> _AddedDllDirectory: ...
    if sys.platform == "linux":
        MFD_CLOEXEC: int
        MFD_ALLOW_SEALING: int
        MFD_HUGETLB: int
        MFD_HUGE_SHIFT: int
        MFD_HUGE_MASK: int
        MFD_HUGE_64KB: int
        MFD_HUGE_512KB: int
        MFD_HUGE_1MB: int
        MFD_HUGE_2MB: int
        MFD_HUGE_8MB: int
        MFD_HUGE_16MB: int
        MFD_HUGE_32MB: int
        MFD_HUGE_256MB: int
        MFD_HUGE_512MB: int
        MFD_HUGE_1GB: int
        MFD_HUGE_2GB: int
        MFD_HUGE_16GB: int
        def memfd_create(name: str, flags: int = ...) -> int: ...
