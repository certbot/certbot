# Stubs for logging.handlers (Python 2.4)

import datetime
from logging import Handler, FileHandler, LogRecord
from socket import SocketType
import ssl
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, overload
if sys.version_info >= (3, 7):
    from queue import SimpleQueue, Queue
elif sys.version_info >= (3,):
    from queue import Queue
else:
    from Queue import Queue

# TODO update socket stubs to add SocketKind
_SocketKind = int
if sys.version_info >= (3, 6):
    from os import PathLike
    _Path = Union[str, PathLike[str]]
else:
    _Path = str

DEFAULT_TCP_LOGGING_PORT: int
DEFAULT_UDP_LOGGING_PORT: int
DEFAULT_HTTP_LOGGING_PORT: int
DEFAULT_SOAP_LOGGING_PORT: int
SYSLOG_UDP_PORT: int
SYSLOG_TCP_PORT: int

class WatchedFileHandler(FileHandler):
    def __init__(self, filename: _Path, mode: str = ..., encoding: Optional[str] = ...,
                 delay: bool = ...) -> None: ...


if sys.version_info >= (3,):
    class BaseRotatingHandler(FileHandler):
        terminator: str
        namer: Optional[Callable[[str], str]]
        rotator: Optional[Callable[[str, str], None]]
        def __init__(self, filename: _Path, mode: str,
                     encoding: Optional[str] = ...,
                     delay: bool = ...) -> None: ...
        def rotation_filename(self, default_name: str) -> None: ...
        def rotate(self, source: str, dest: str) -> None: ...


if sys.version_info >= (3,):
    class RotatingFileHandler(BaseRotatingHandler):
        def __init__(self, filename: _Path, mode: str = ..., maxBytes: int = ...,
                     backupCount: int = ..., encoding: Optional[str] = ...,
                     delay: bool = ...) -> None: ...
        def doRollover(self) -> None: ...
else:
    class RotatingFileHandler(Handler):
        def __init__(self, filename: str, mode: str = ..., maxBytes: int = ...,
                     backupCount: int = ..., encoding: Optional[str] = ...,
                     delay: bool = ...) -> None: ...
        def doRollover(self) -> None: ...


if sys.version_info >= (3,):
    class TimedRotatingFileHandler(BaseRotatingHandler):
        if sys.version_info >= (3, 4):
            def __init__(self, filename: _Path, when: str = ...,
                         interval: int = ...,
                         backupCount: int = ..., encoding: Optional[str] = ...,
                         delay: bool = ..., utc: bool = ...,
                         atTime: Optional[datetime.datetime] = ...) -> None: ...
        else:
            def __init__(self,
                         filename: str, when: str = ..., interval: int = ...,
                         backupCount: int = ..., encoding: Optional[str] = ...,
                         delay: bool = ..., utc: bool = ...) -> None: ...
        def doRollover(self) -> None: ...
else:
    class TimedRotatingFileHandler(Handler):
        def __init__(self,
                     filename: str, when: str = ..., interval: int = ...,
                     backupCount: int = ..., encoding: Optional[str] = ...,
                     delay: bool = ..., utc: bool = ...) -> None: ...
        def doRollover(self) -> None: ...


class SocketHandler(Handler):
    retryStart: float
    retryFactor: float
    retryMax: float
    if sys.version_info >= (3, 4):
        def __init__(self, host: str, port: Optional[int]) -> None: ...
    else:
        def __init__(self, host: str, port: int) -> None: ...
    def makeSocket(self) -> SocketType: ...
    def makePickle(self, record: LogRecord) -> bytes: ...
    def send(self, packet: bytes) -> None: ...
    def createSocket(self) -> None: ...


class DatagramHandler(SocketHandler): ...


class SysLogHandler(Handler):
    LOG_ALERT: int
    LOG_CRIT: int
    LOG_DEBUG: int
    LOG_EMERG: int
    LOG_ERR: int
    LOG_INFO: int
    LOG_NOTICE: int
    LOG_WARNING: int
    LOG_AUTH: int
    LOG_AUTHPRIV: int
    LOG_CRON: int
    LOG_DAEMON: int
    LOG_FTP: int
    LOG_KERN: int
    LOG_LPR: int
    LOG_MAIL: int
    LOG_NEWS: int
    LOG_SYSLOG: int
    LOG_USER: int
    LOG_UUCP: int
    LOG_LOCAL0: int
    LOG_LOCAL1: int
    LOG_LOCAL2: int
    LOG_LOCAL3: int
    LOG_LOCAL4: int
    LOG_LOCAL5: int
    LOG_LOCAL6: int
    LOG_LOCAL7: int
    def __init__(self, address: Union[Tuple[str, int], str] = ...,
                 facility: int = ..., socktype: _SocketKind = ...) -> None: ...
    def encodePriority(self, facility: Union[int, str],
                       priority: Union[int, str]) -> int: ...
    def mapPriority(self, levelName: str) -> str: ...


class NTEventLogHandler(Handler):
    def __init__(self, appname: str, dllname: str = ...,
                 logtype: str = ...) -> None: ...
    def getEventCategory(self, record: LogRecord) -> int: ...
    # TODO correct return value?
    def getEventType(self, record: LogRecord) -> int: ...
    def getMessageID(self, record: LogRecord) -> int: ...


class SMTPHandler(Handler):
    # TODO `secure` can also be an empty tuple
    if sys.version_info >= (3,):
        def __init__(self, mailhost: Union[str, Tuple[str, int]], fromaddr: str,
                     toaddrs: List[str], subject: str,
                     credentials: Optional[Tuple[str, str]] = ...,
                     secure: Union[Tuple[str], Tuple[str, str], None] = ...,
                     timeout: float = ...) -> None: ...
    else:
        def __init__(self,
                     mailhost: Union[str, Tuple[str, int]], fromaddr: str,
                     toaddrs: List[str], subject: str,
                     credentials: Optional[Tuple[str, str]] = ...,
                     secure: Union[Tuple[str], Tuple[str, str], None] = ...) -> None: ...
    def getSubject(self, record: LogRecord) -> str: ...


class BufferingHandler(Handler):
    buffer: List[LogRecord]
    def __init__(self, capacity: int) -> None: ...
    def shouldFlush(self, record: LogRecord) -> bool: ...

class MemoryHandler(BufferingHandler):
    def __init__(self, capacity: int, flushLevel: int = ...,
                 target: Optional[Handler] = ...) -> None: ...
    def setTarget(self, target: Handler) -> None: ...


class HTTPHandler(Handler):
    if sys.version_info >= (3, 5):
        def __init__(self, host: str, url: str, method: str = ...,
                     secure: bool = ...,
                     credentials: Optional[Tuple[str, str]] = ...,
                     context: Optional[ssl.SSLContext] = ...) -> None: ...
    elif sys.version_info >= (3,):
        def __init__(self,
                     host: str, url: str, method: str = ..., secure: bool = ...,
                     credentials: Optional[Tuple[str, str]] = ...) -> None: ...
    else:
        def __init__(self,
                     host: str, url: str, method: str = ...) -> None: ...
    def mapLogRecord(self, record: LogRecord) -> Dict[str, Any]: ...


if sys.version_info >= (3,):
    class QueueHandler(Handler):
        if sys.version_info >= (3, 7):
            def __init__(self, queue: Union[SimpleQueue[Any], Queue[Any]]) -> None: ...
        else:
            def __init__(self, queue: Queue[Any]) -> None: ...
        def prepare(self, record: LogRecord) -> Any: ...
        def enqueue(self, record: LogRecord) -> None: ...

    class QueueListener:
        if sys.version_info >= (3, 7):
            def __init__(self, queue: Union[SimpleQueue[Any], Queue[Any]],
                         *handlers: Handler,
                         respect_handler_level: bool = ...) -> None: ...
        elif sys.version_info >= (3, 5):
            def __init__(self, queue: Queue[Any], *handlers: Handler,
                         respect_handler_level: bool = ...) -> None: ...
        else:
            def __init__(self,
                         queue: Queue, *handlers: Handler) -> None: ...
        def dequeue(self, block: bool) -> LogRecord: ...
        def prepare(self, record: LogRecord) -> Any: ...
        def start(self) -> None: ...
        def stop(self) -> None: ...
        def enqueue_sentinel(self) -> None: ...
