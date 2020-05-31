# Stubs for resource

# NOTE: These are incomplete!

from typing import Tuple, Optional, NamedTuple

RLIMIT_AS: int
RLIMIT_CORE: int
RLIMIT_CPU: int
RLIMIT_DATA: int
RLIMIT_FSIZE: int
RLIMIT_MEMLOCK: int
RLIMIT_MSGQUEUE: int
RLIMIT_NICE: int
RLIMIT_NOFILE: int
RLIMIT_NPROC: int
RLIMIT_OFILE: int
RLIMIT_RSS: int
RLIMIT_RTPRIO: int
RLIMIT_RTTIME: int
RLIMIT_SIGPENDING: int
RLIMIT_STACK: int
RLIM_INFINITY: int
RUSAGE_CHILDREN: int
RUSAGE_SELF: int
RUSAGE_THREAD: int

class _RUsage(NamedTuple):
    ru_utime: float
    ru_stime: float
    ru_maxrss: int
    ru_ixrss: int
    ru_idrss: int
    ru_isrss: int
    ru_minflt: int
    ru_majflt: int
    ru_nswap: int
    ru_inblock: int
    ru_oublock: int
    ru_msgsnd: int
    ru_msgrcv: int
    ru_nsignals: int
    ru_nvcsw: int
    ru_nivcsw: int

def getpagesize() -> int: ...
def getrlimit(resource: int) -> Tuple[int, int]: ...
def getrusage(who: int) -> _RUsage: ...
def prlimit(pid: int, resource: int, limits: Optional[Tuple[int, int]]) -> Tuple[int, int]: ...
def setrlimit(resource: int, limits: Tuple[int, int]) -> None: ...

# NOTE: This is an alias of OSError in Python 3.3.
class error(Exception): ...
