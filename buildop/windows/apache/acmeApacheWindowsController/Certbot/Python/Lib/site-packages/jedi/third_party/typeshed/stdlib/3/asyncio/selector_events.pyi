import selectors
import sys
from socket import socket
from typing import Optional, Union

from . import base_events, events

if sys.version_info >= (3, 7):
    from os import PathLike
    _Path = Union[str, PathLike[str]]
else:
    _Path = str

class BaseSelectorEventLoop(base_events.BaseEventLoop):

    def __init__(self, selector: selectors.BaseSelector = ...) -> None: ...
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
