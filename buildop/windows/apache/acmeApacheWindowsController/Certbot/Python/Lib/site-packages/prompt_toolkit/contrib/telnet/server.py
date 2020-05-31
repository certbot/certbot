"""
Telnet server.
"""
import asyncio
import contextvars  # Requires Python3.7!
import socket
from asyncio import get_event_loop
from typing import Awaitable, Callable, List, Optional, Set, TextIO, Tuple, cast

from prompt_toolkit.application.current import create_app_session, get_app
from prompt_toolkit.application.run_in_terminal import run_in_terminal
from prompt_toolkit.data_structures import Size
from prompt_toolkit.formatted_text import AnyFormattedText, to_formatted_text
from prompt_toolkit.input.posix_pipe import PosixPipeInput
from prompt_toolkit.output.vt100 import Vt100_Output
from prompt_toolkit.renderer import print_formatted_text as print_formatted_text
from prompt_toolkit.styles import BaseStyle, DummyStyle

from .log import logger
from .protocol import (
    DO,
    ECHO,
    IAC,
    LINEMODE,
    MODE,
    NAWS,
    SB,
    SE,
    SUPPRESS_GO_AHEAD,
    WILL,
    TelnetProtocolParser,
)

__all__ = [
    "TelnetServer",
]


def int2byte(number: int) -> bytes:
    return bytes((number,))


def _initialize_telnet(connection: socket.socket) -> None:
    logger.info("Initializing telnet connection")

    # Iac Do Linemode
    connection.send(IAC + DO + LINEMODE)

    # Suppress Go Ahead. (This seems important for Putty to do correct echoing.)
    # This will allow bi-directional operation.
    connection.send(IAC + WILL + SUPPRESS_GO_AHEAD)

    # Iac sb
    connection.send(IAC + SB + LINEMODE + MODE + int2byte(0) + IAC + SE)

    # IAC Will Echo
    connection.send(IAC + WILL + ECHO)

    # Negotiate window size
    connection.send(IAC + DO + NAWS)


class _ConnectionStdout:
    """
    Wrapper around socket which provides `write` and `flush` methods for the
    Vt100_Output output.
    """

    def __init__(self, connection: socket.socket, encoding: str) -> None:
        self._encoding = encoding
        self._connection = connection
        self._errors = "strict"
        self._buffer: List[bytes] = []

    def write(self, data: str) -> None:
        self._buffer.append(data.encode(self._encoding, errors=self._errors))
        self.flush()

    def flush(self) -> None:
        try:
            self._connection.send(b"".join(self._buffer))
        except socket.error as e:
            logger.warning("Couldn't send data over socket: %s" % e)

        self._buffer = []

    @property
    def encoding(self) -> str:
        return self._encoding

    @property
    def errors(self) -> str:
        return self._errors


class TelnetConnection:
    """
    Class that represents one Telnet connection.
    """

    def __init__(
        self,
        conn: socket.socket,
        addr: Tuple[str, int],
        interact: Callable[["TelnetConnection"], Awaitable[None]],
        server: "TelnetServer",
        encoding: str,
        style: Optional[BaseStyle],
    ) -> None:

        self.conn = conn
        self.addr = addr
        self.interact = interact
        self.server = server
        self.encoding = encoding
        self.style = style
        self._closed = False

        # Create "Output" object.
        self.size = Size(rows=40, columns=79)

        # Initialize.
        _initialize_telnet(conn)

        # Create input.
        self.vt100_input = PosixPipeInput()

        # Create output.
        def get_size() -> Size:
            return self.size

        self.stdout = cast(TextIO, _ConnectionStdout(conn, encoding=encoding))
        self.vt100_output = Vt100_Output(self.stdout, get_size, write_binary=False)

        def data_received(data: bytes) -> None:
            """ TelnetProtocolParser 'data_received' callback """
            self.vt100_input.send_bytes(data)

        def size_received(rows: int, columns: int) -> None:
            """ TelnetProtocolParser 'size_received' callback """
            self.size = Size(rows=rows, columns=columns)
            get_app()._on_resize()

        self.parser = TelnetProtocolParser(data_received, size_received)
        self.context: Optional[contextvars.Context] = None

    async def run_application(self) -> None:
        """
        Run application.
        """

        def handle_incoming_data() -> None:
            data = self.conn.recv(1024)
            if data:
                self.feed(data)
            else:
                # Connection closed by client.
                logger.info("Connection closed by client. %r %r" % self.addr)
                self.close()

        async def run() -> None:
            # Add reader.
            loop = get_event_loop()
            loop.add_reader(self.conn, handle_incoming_data)

            try:
                await self.interact(self)
            except Exception as e:
                print("Got %s" % type(e).__name__, e)
                import traceback

                traceback.print_exc()
                raise
            finally:
                self.close()

        with create_app_session(input=self.vt100_input, output=self.vt100_output):
            self.context = contextvars.copy_context()
            await run()

    def feed(self, data: bytes) -> None:
        """
        Handler for incoming data. (Called by TelnetServer.)
        """
        self.parser.feed(data)

    def close(self) -> None:
        """
        Closed by client.
        """
        if not self._closed:
            self._closed = True

            self.vt100_input.close()
            get_event_loop().remove_reader(self.conn)
            self.conn.close()

    def send(self, formatted_text: AnyFormattedText) -> None:
        """
        Send text to the client.
        """
        formatted_text = to_formatted_text(formatted_text)
        print_formatted_text(
            self.vt100_output, formatted_text, self.style or DummyStyle()
        )

    def send_above_prompt(self, formatted_text: AnyFormattedText) -> None:
        """
        Send text to the client.
        This is asynchronous, returns a `Future`.
        """
        formatted_text = to_formatted_text(formatted_text)
        return self._run_in_terminal(lambda: self.send(formatted_text))

    def _run_in_terminal(self, func: Callable[[], None]) -> None:
        # Make sure that when an application was active for this connection,
        # that we print the text above the application.
        if self.context:
            self.context.run(run_in_terminal, func)
        else:
            raise RuntimeError("Called _run_in_terminal outside `run_application`.")

    def erase_screen(self) -> None:
        """
        Erase the screen and move the cursor to the top.
        """
        self.vt100_output.erase_screen()
        self.vt100_output.cursor_goto(0, 0)
        self.vt100_output.flush()


async def _dummy_interact(connection: TelnetConnection) -> None:
    pass


class TelnetServer:
    """
    Telnet server implementation.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 23,
        interact: Callable[[TelnetConnection], Awaitable[None]] = _dummy_interact,
        encoding: str = "utf-8",
        style: Optional[BaseStyle] = None,
    ) -> None:

        self.host = host
        self.port = port
        self.interact = interact
        self.encoding = encoding
        self.style = style
        self._application_tasks: List[asyncio.Task] = []

        self.connections: Set[TelnetConnection] = set()
        self._listen_socket: Optional[socket.socket] = None

    @classmethod
    def _create_socket(cls, host: str, port: int) -> socket.socket:
        # Create and bind socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))

        s.listen(4)
        return s

    def start(self) -> None:
        """
        Start the telnet server.
        Don't forget to call `loop.run_forever()` after doing this.
        """
        self._listen_socket = self._create_socket(self.host, self.port)
        logger.info(
            "Listening for telnet connections on %s port %r", self.host, self.port
        )

        get_event_loop().add_reader(self._listen_socket, self._accept)

    async def stop(self) -> None:
        if self._listen_socket:
            get_event_loop().remove_reader(self._listen_socket)
            self._listen_socket.close()

        # Wait for all applications to finish.
        for t in self._application_tasks:
            t.cancel()

        for t in self._application_tasks:
            await t

    def _accept(self) -> None:
        """
        Accept new incoming connection.
        """
        if self._listen_socket is None:
            return  # Should not happen. `_accept` is called after `start`.

        conn, addr = self._listen_socket.accept()
        logger.info("New connection %r %r", *addr)

        connection = TelnetConnection(
            conn, addr, self.interact, self, encoding=self.encoding, style=self.style
        )
        self.connections.add(connection)

        # Run application for this connection.
        async def run() -> None:
            logger.info("Starting interaction %r %r", *addr)
            try:
                await connection.run_application()
            except Exception as e:
                print(e)
            finally:
                self.connections.remove(connection)
                self._application_tasks.remove(task)
                logger.info("Stopping interaction %r %r", *addr)

        task = get_event_loop().create_task(run())
        self._application_tasks.append(task)
