import sys
from socket import socket
from typing import Any, Mapping, Optional, Union

from . import base_events, constants, events, futures, streams, transports

if sys.version_info >= (3, 7):
    from os import PathLike
    _Path = Union[str, PathLike[str]]
else:
    _Path = str

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

class _ProactorBasePipeTransport(transports._FlowControlMixin, transports.BaseTransport):

    def __init__(self, loop: events.AbstractEventLoop, sock: socket, protocol: streams.StreamReaderProtocol, waiter: Optional[futures.Future[Any]] = ..., extra: Optional[Mapping[Any, Any]] = ..., server: Optional[events.AbstractServer] = ...) -> None: ...
    def __repr__(self) -> str: ...
    def __del__(self) -> None: ...
    def get_write_buffer_size(self) -> int: ...

class _ProactorReadPipeTransport(_ProactorBasePipeTransport, transports.ReadTransport):

    def __init__(self, loop: events.AbstractEventLoop, sock: socket, protocol: streams.StreamReaderProtocol, waiter: Optional[futures.Future[Any]] = ..., extra: Optional[Mapping[Any, Any]] = ..., server: Optional[events.AbstractServer] = ...) -> None: ...

class _ProactorBaseWritePipeTransport(_ProactorBasePipeTransport, transports.WriteTransport):

    def __init__(self, loop: events.AbstractEventLoop, sock: socket, protocol: streams.StreamReaderProtocol, waiter: Optional[futures.Future[Any]] = ..., extra: Optional[Mapping[Any, Any]] = ..., server: Optional[events.AbstractServer] = ...) -> None: ...

class _ProactorWritePipeTransport(_ProactorBaseWritePipeTransport):

    def __init__(self, loop: events.AbstractEventLoop, sock: socket, protocol: streams.StreamReaderProtocol, waiter: Optional[futures.Future[Any]] = ..., extra: Optional[Mapping[Any, Any]] = ..., server: Optional[events.AbstractServer] = ...) -> None: ...

class _ProactorDuplexPipeTransport(_ProactorReadPipeTransport, _ProactorBaseWritePipeTransport, transports.Transport): ...

class _ProactorSocketTransport(_ProactorReadPipeTransport, _ProactorBaseWritePipeTransport, transports.Transport):

    _sendfile_compatible: constants._SendfileMode = ...

    def __init__(self, loop: events.AbstractEventLoop, sock: socket, protocol: streams.StreamReaderProtocol, waiter: Optional[futures.Future[Any]] = ..., extra: Optional[Mapping[Any, Any]] = ..., server: Optional[events.AbstractServer] = ...) -> None: ...
    def _set_extra(self, sock: socket) -> None: ...
    def can_write_eof(self) -> Literal[True]: ...
    def write_eof(self) -> None: ...

class BaseProactorEventLoop(base_events.BaseEventLoop):

    def __init__(self, proactor: Any) -> None: ...
    # The methods below don't actually exist directly, ProactorEventLoops do not implement them. However, they are
    # needed to satisfy mypy
    if sys.version_info >= (3, 7):
        async def create_unix_connection(
            self,
            protocol_factory: events._ProtocolFactory,
            path: _Path,
            *,
            ssl: events._SSLContext = ...,
            sock: Optional[socket] = ...,
            server_hostname: str = ...,
            ssl_handshake_timeout: Optional[float] = ...,
        ) -> events._TransProtPair: ...
        async def create_unix_server(
            self,
            protocol_factory: events._ProtocolFactory,
            path: _Path,
            *,
            sock: Optional[socket] = ...,
            backlog: int = ...,
            ssl: events._SSLContext = ...,
            ssl_handshake_timeout: Optional[float] = ...,
            start_serving: bool = ...,
        ) -> events.AbstractServer: ...
    else:
        async def create_unix_connection(self, protocol_factory: events._ProtocolFactory, path: str, *,
                                         ssl: events._SSLContext = ..., sock: Optional[socket] = ...,
                                         server_hostname: str = ...) -> events._TransProtPair: ...
        async def create_unix_server(self, protocol_factory: events._ProtocolFactory, path: str, *,
                                     sock: Optional[socket] = ..., backlog: int = ..., ssl: events._SSLContext = ...) -> events.AbstractServer: ...
