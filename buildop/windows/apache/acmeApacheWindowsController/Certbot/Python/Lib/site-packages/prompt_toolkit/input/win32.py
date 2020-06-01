import msvcrt
import os
import sys
from abc import abstractmethod
from asyncio import get_event_loop
from contextlib import contextmanager
from ctypes import pointer, windll
from ctypes.wintypes import DWORD, HANDLE
from typing import Callable, ContextManager, Dict, Iterable, Optional, TextIO

from prompt_toolkit.eventloop import run_in_executor_with_context
from prompt_toolkit.eventloop.win32 import create_win32_event, wait_for_handles
from prompt_toolkit.key_binding.key_processor import KeyPress
from prompt_toolkit.keys import Keys
from prompt_toolkit.mouse_events import MouseEventType
from prompt_toolkit.win32_types import (
    INPUT_RECORD,
    KEY_EVENT_RECORD,
    MOUSE_EVENT_RECORD,
    STD_INPUT_HANDLE,
    EventTypes,
)

from .ansi_escape_sequences import REVERSE_ANSI_SEQUENCES
from .base import Input

__all__ = [
    "Win32Input",
    "ConsoleInputReader",
    "raw_mode",
    "cooked_mode",
    "attach_win32_input",
    "detach_win32_input",
]


class _Win32InputBase(Input):
    """
    Base class for `Win32Input` and `Win32PipeInput`.
    """

    def __init__(self) -> None:
        self.win32_handles = _Win32Handles()

    @property
    @abstractmethod
    def handle(self) -> HANDLE:
        pass


class Win32Input(_Win32InputBase):
    """
    `Input` class that reads from the Windows console.
    """

    def __init__(self, stdin: Optional[TextIO] = None) -> None:
        super().__init__()
        self.console_input_reader = ConsoleInputReader()

    def attach(self, input_ready_callback: Callable[[], None]) -> ContextManager[None]:
        """
        Return a context manager that makes this input active in the current
        event loop.
        """
        return attach_win32_input(self, input_ready_callback)

    def detach(self) -> ContextManager[None]:
        """
        Return a context manager that makes sure that this input is not active
        in the current event loop.
        """
        return detach_win32_input(self)

    def read_keys(self):
        return list(self.console_input_reader.read())

    def flush(self) -> None:
        pass

    @property
    def closed(self) -> bool:
        return False

    def raw_mode(self) -> ContextManager[None]:
        return raw_mode()

    def cooked_mode(self) -> ContextManager[None]:
        return cooked_mode()

    def fileno(self) -> int:
        # The windows console doesn't depend on the file handle, so
        # this is not used for the event loop (which uses the
        # handle instead). But it's used in `Application.run_system_command`
        # which opens a subprocess with a given stdin/stdout.
        return sys.stdin.fileno()

    def typeahead_hash(self) -> str:
        return "win32-input"

    def close(self) -> None:
        self.console_input_reader.close()

    @property
    def handle(self) -> HANDLE:
        return self.console_input_reader.handle


class ConsoleInputReader:
    """
    :param recognize_paste: When True, try to discover paste actions and turn
        the event into a BracketedPaste.
    """

    # Keys with character data.
    mappings = {
        b"\x1b": Keys.Escape,
        b"\x00": Keys.ControlSpace,  # Control-Space (Also for Ctrl-@)
        b"\x01": Keys.ControlA,  # Control-A (home)
        b"\x02": Keys.ControlB,  # Control-B (emacs cursor left)
        b"\x03": Keys.ControlC,  # Control-C (interrupt)
        b"\x04": Keys.ControlD,  # Control-D (exit)
        b"\x05": Keys.ControlE,  # Control-E (end)
        b"\x06": Keys.ControlF,  # Control-F (cursor forward)
        b"\x07": Keys.ControlG,  # Control-G
        b"\x08": Keys.ControlH,  # Control-H (8) (Identical to '\b')
        b"\x09": Keys.ControlI,  # Control-I (9) (Identical to '\t')
        b"\x0a": Keys.ControlJ,  # Control-J (10) (Identical to '\n')
        b"\x0b": Keys.ControlK,  # Control-K (delete until end of line; vertical tab)
        b"\x0c": Keys.ControlL,  # Control-L (clear; form feed)
        b"\x0d": Keys.ControlM,  # Control-M (enter)
        b"\x0e": Keys.ControlN,  # Control-N (14) (history forward)
        b"\x0f": Keys.ControlO,  # Control-O (15)
        b"\x10": Keys.ControlP,  # Control-P (16) (history back)
        b"\x11": Keys.ControlQ,  # Control-Q
        b"\x12": Keys.ControlR,  # Control-R (18) (reverse search)
        b"\x13": Keys.ControlS,  # Control-S (19) (forward search)
        b"\x14": Keys.ControlT,  # Control-T
        b"\x15": Keys.ControlU,  # Control-U
        b"\x16": Keys.ControlV,  # Control-V
        b"\x17": Keys.ControlW,  # Control-W
        b"\x18": Keys.ControlX,  # Control-X
        b"\x19": Keys.ControlY,  # Control-Y (25)
        b"\x1a": Keys.ControlZ,  # Control-Z
        b"\x1c": Keys.ControlBackslash,  # Both Control-\ and Ctrl-|
        b"\x1d": Keys.ControlSquareClose,  # Control-]
        b"\x1e": Keys.ControlCircumflex,  # Control-^
        b"\x1f": Keys.ControlUnderscore,  # Control-underscore (Also for Ctrl-hyphen.)
        b"\x7f": Keys.Backspace,  # (127) Backspace   (ASCII Delete.)
    }

    # Keys that don't carry character data.
    keycodes = {
        # Home/End
        33: Keys.PageUp,
        34: Keys.PageDown,
        35: Keys.End,
        36: Keys.Home,
        # Arrows
        37: Keys.Left,
        38: Keys.Up,
        39: Keys.Right,
        40: Keys.Down,
        45: Keys.Insert,
        46: Keys.Delete,
        # F-keys.
        112: Keys.F1,
        113: Keys.F2,
        114: Keys.F3,
        115: Keys.F4,
        116: Keys.F5,
        117: Keys.F6,
        118: Keys.F7,
        119: Keys.F8,
        120: Keys.F9,
        121: Keys.F10,
        122: Keys.F11,
        123: Keys.F12,
    }

    LEFT_ALT_PRESSED = 0x0002
    RIGHT_ALT_PRESSED = 0x0001
    SHIFT_PRESSED = 0x0010
    LEFT_CTRL_PRESSED = 0x0008
    RIGHT_CTRL_PRESSED = 0x0004

    def __init__(self, recognize_paste: bool = True) -> None:
        self._fdcon = None
        self.recognize_paste = recognize_paste

        # When stdin is a tty, use that handle, otherwise, create a handle from
        # CONIN$.
        self.handle: HANDLE
        if sys.stdin.isatty():
            self.handle = HANDLE(windll.kernel32.GetStdHandle(STD_INPUT_HANDLE))
        else:
            self._fdcon = os.open("CONIN$", os.O_RDWR | os.O_BINARY)
            self.handle = HANDLE(msvcrt.get_osfhandle(self._fdcon))

    def close(self) -> None:
        " Close fdcon. "
        if self._fdcon is not None:
            os.close(self._fdcon)

    def read(self) -> Iterable[KeyPress]:
        """
        Return a list of `KeyPress` instances. It won't return anything when
        there was nothing to read.  (This function doesn't block.)

        http://msdn.microsoft.com/en-us/library/windows/desktop/ms684961(v=vs.85).aspx
        """
        max_count = 2048  # Max events to read at the same time.

        read = DWORD(0)
        arrtype = INPUT_RECORD * max_count
        input_records = arrtype()

        # Check whether there is some input to read. `ReadConsoleInputW` would
        # block otherwise.
        # (Actually, the event loop is responsible to make sure that this
        # function is only called when there is something to read, but for some
        # reason this happened in the asyncio_win32 loop, and it's better to be
        # safe anyway.)
        if not wait_for_handles([self.handle], timeout=0):
            return

        # Get next batch of input event.
        windll.kernel32.ReadConsoleInputW(
            self.handle, pointer(input_records), max_count, pointer(read)
        )

        # First, get all the keys from the input buffer, in order to determine
        # whether we should consider this a paste event or not.
        all_keys = list(self._get_keys(read, input_records))

        # Fill in 'data' for key presses.
        all_keys = [self._insert_key_data(key) for key in all_keys]

        if self.recognize_paste and self._is_paste(all_keys):
            gen = iter(all_keys)
            k: Optional[KeyPress]

            for k in gen:
                # Pasting: if the current key consists of text or \n, turn it
                # into a BracketedPaste.
                data = []
                while k and (isinstance(k.key, str) or k.key == Keys.ControlJ):
                    data.append(k.data)
                    try:
                        k = next(gen)
                    except StopIteration:
                        k = None

                if data:
                    yield KeyPress(Keys.BracketedPaste, "".join(data))
                if k is not None:
                    yield k
        else:
            for k2 in all_keys:
                yield k2

    def _insert_key_data(self, key_press: KeyPress) -> KeyPress:
        """
        Insert KeyPress data, for vt100 compatibility.
        """
        if key_press.data:
            return key_press

        if isinstance(key_press.key, Keys):
            data = REVERSE_ANSI_SEQUENCES.get(key_press.key, "")
        else:
            data = ""

        return KeyPress(key_press.key, data)

    def _get_keys(self, read, input_records):
        """
        Generator that yields `KeyPress` objects from the input records.
        """
        for i in range(read.value):
            ir = input_records[i]

            # Get the right EventType from the EVENT_RECORD.
            # (For some reason the Windows console application 'cmder'
            # [http://gooseberrycreative.com/cmder/] can return '0' for
            # ir.EventType. -- Just ignore that.)
            if ir.EventType in EventTypes:
                ev = getattr(ir.Event, EventTypes[ir.EventType])

                # Process if this is a key event. (We also have mouse, menu and
                # focus events.)
                if type(ev) == KEY_EVENT_RECORD and ev.KeyDown:
                    for key_press in self._event_to_key_presses(ev):
                        yield key_press

                elif type(ev) == MOUSE_EVENT_RECORD:
                    for key_press in self._handle_mouse(ev):
                        yield key_press

    @staticmethod
    def _is_paste(keys) -> bool:
        """
        Return `True` when we should consider this list of keys as a paste
        event. Pasted text on windows will be turned into a
        `Keys.BracketedPaste` event. (It's not 100% correct, but it is probably
        the best possible way to detect pasting of text and handle that
        correctly.)
        """
        # Consider paste when it contains at least one newline and at least one
        # other character.
        text_count = 0
        newline_count = 0

        for k in keys:
            if isinstance(k.key, str):
                text_count += 1
            if k.key == Keys.ControlM:
                newline_count += 1

        return newline_count >= 1 and text_count > 1

    def _event_to_key_presses(self, ev):
        """
        For this `KEY_EVENT_RECORD`, return a list of `KeyPress` instances.
        """
        assert type(ev) == KEY_EVENT_RECORD and ev.KeyDown

        result = None

        u_char = ev.uChar.UnicodeChar
        ascii_char = u_char.encode("utf-8")

        # NOTE: We don't use `ev.uChar.AsciiChar`. That appears to be latin-1
        #       encoded. See also:
        # https://github.com/ipython/ipython/issues/10004
        # https://github.com/jonathanslenders/python-prompt-toolkit/issues/389

        if u_char == "\x00":
            if ev.VirtualKeyCode in self.keycodes:
                result = KeyPress(self.keycodes[ev.VirtualKeyCode], "")
        else:
            if ascii_char in self.mappings:
                if self.mappings[ascii_char] == Keys.ControlJ:
                    u_char = (
                        "\n"  # Windows sends \n, turn into \r for unix compatibility.
                    )
                result = KeyPress(self.mappings[ascii_char], u_char)
            else:
                result = KeyPress(u_char, u_char)

        # First we handle Shift-Control-Arrow/Home/End (need to do this first)
        if (
            (
                ev.ControlKeyState & self.LEFT_CTRL_PRESSED
                or ev.ControlKeyState & self.RIGHT_CTRL_PRESSED
            )
            and ev.ControlKeyState & self.SHIFT_PRESSED
            and result
        ):
            result.key = {
                Keys.Left: Keys.ControlShiftLeft,
                Keys.Right: Keys.ControlShiftRight,
                Keys.Up: Keys.ControlShiftUp,
                Keys.Down: Keys.ControlShiftDown,
                Keys.Home: Keys.ControlShiftHome,
                Keys.End: Keys.ControlShiftEnd,
                Keys.Insert: Keys.ControlShiftInsert,
                Keys.PageUp: Keys.ControlShiftPageUp,
                Keys.PageDown: Keys.ControlShiftPageDown,
            }.get(result.key, result.key)

        # Correctly handle Control-Arrow/Home/End and Control-Insert keys.
        if (
            ev.ControlKeyState & self.LEFT_CTRL_PRESSED
            or ev.ControlKeyState & self.RIGHT_CTRL_PRESSED
        ) and result:
            result.key = {
                Keys.Left: Keys.ControlLeft,
                Keys.Right: Keys.ControlRight,
                Keys.Up: Keys.ControlUp,
                Keys.Down: Keys.ControlDown,
                Keys.Home: Keys.ControlHome,
                Keys.End: Keys.ControlEnd,
                Keys.Insert: Keys.ControlInsert,
                Keys.PageUp: Keys.ControlPageUp,
                Keys.PageDown: Keys.ControlPageDown,
            }.get(result.key, result.key)

        # Turn 'Tab' into 'BackTab' when shift was pressed.
        # Also handle other shift-key combination
        if ev.ControlKeyState & self.SHIFT_PRESSED and result:
            result.key = {
                Keys.Tab: Keys.BackTab,
                Keys.Left: Keys.ShiftLeft,
                Keys.Right: Keys.ShiftRight,
                Keys.Up: Keys.ShiftUp,
                Keys.Down: Keys.ShiftDown,
                Keys.Home: Keys.ShiftHome,
                Keys.End: Keys.ShiftEnd,
                Keys.Insert: Keys.ShiftInsert,
                Keys.PageUp: Keys.ShiftPageUp,
                Keys.PageDown: Keys.ShiftPageDown,
            }.get(result.key, result.key)

        # Turn 'Space' into 'ControlSpace' when control was pressed.
        if (
            (
                ev.ControlKeyState & self.LEFT_CTRL_PRESSED
                or ev.ControlKeyState & self.RIGHT_CTRL_PRESSED
            )
            and result
            and result.data == " "
        ):
            result = KeyPress(Keys.ControlSpace, " ")

        # Turn Control-Enter into META-Enter. (On a vt100 terminal, we cannot
        # detect this combination. But it's really practical on Windows.)
        if (
            (
                ev.ControlKeyState & self.LEFT_CTRL_PRESSED
                or ev.ControlKeyState & self.RIGHT_CTRL_PRESSED
            )
            and result
            and result.key == Keys.ControlJ
        ):
            return [KeyPress(Keys.Escape, ""), result]

        # Return result. If alt was pressed, prefix the result with an
        # 'Escape' key, just like unix VT100 terminals do.

        # NOTE: Only replace the left alt with escape. The right alt key often
        #       acts as altgr and is used in many non US keyboard layouts for
        #       typing some special characters, like a backslash. We don't want
        #       all backslashes to be prefixed with escape. (Esc-\ has a
        #       meaning in E-macs, for instance.)
        if result:
            meta_pressed = ev.ControlKeyState & self.LEFT_ALT_PRESSED

            if meta_pressed:
                return [KeyPress(Keys.Escape, ""), result]
            else:
                return [result]

        else:
            return []

    def _handle_mouse(self, ev):
        """
        Handle mouse events. Return a list of KeyPress instances.
        """
        FROM_LEFT_1ST_BUTTON_PRESSED = 0x1

        result = []

        # Check event type.
        if ev.ButtonState == FROM_LEFT_1ST_BUTTON_PRESSED:
            # On a key press, generate both the mouse down and up event.
            for event_type in [MouseEventType.MOUSE_DOWN, MouseEventType.MOUSE_UP]:
                data = ";".join(
                    [event_type.value, str(ev.MousePosition.X), str(ev.MousePosition.Y)]
                )
                result.append(KeyPress(Keys.WindowsMouseEvent, data))

        return result


class _Win32Handles:
    """
    Utility to keep track of which handles are connectod to which callbacks.

    `add_win32_handle` starts a tiny event loop in another thread which waits
    for the Win32 handle to become ready. When this happens, the callback will
    be called in the current asyncio event loop using `call_soon_threadsafe`.

    `remove_win32_handle` will stop this tiny event loop.

    NOTE: We use this technique, so that we don't have to use the
          `ProactorEventLoop` on Windows and we can wait for things like stdin
          in a `SelectorEventLoop`. This is important, because our inputhook
          mechanism (used by IPython), only works with the `SelectorEventLoop`.
    """

    def __init__(self) -> None:
        self._handle_callbacks: Dict[int, Callable[[], None]] = {}

        # Windows Events that are triggered when we have to stop watching this
        # handle.
        self._remove_events: Dict[int, HANDLE] = {}

    def add_win32_handle(self, handle: HANDLE, callback: Callable[[], None]) -> None:
        """
        Add a Win32 handle to the event loop.
        """
        handle_value = handle.value

        if handle_value is None:
            raise ValueError("Invalid handle.")

        # Make sure to remove a previous registered handler first.
        self.remove_win32_handle(handle)

        loop = get_event_loop()
        self._handle_callbacks[handle_value] = callback

        # Create remove event.
        remove_event = create_win32_event()
        self._remove_events[handle_value] = remove_event

        # Add reader.
        def ready() -> None:
            # Tell the callback that input's ready.
            try:
                callback()
            finally:
                run_in_executor_with_context(wait, loop=loop)

        # Wait for the input to become ready.
        # (Use an executor for this, the Windows asyncio event loop doesn't
        # allow us to wait for handles like stdin.)
        def wait() -> None:
            # Wait until either the handle becomes ready, or the remove event
            # has been set.
            result = wait_for_handles([remove_event, handle])

            if result is remove_event:
                windll.kernel32.CloseHandle(remove_event)
                return
            else:
                loop.call_soon_threadsafe(ready)

        run_in_executor_with_context(wait, loop=loop)

    def remove_win32_handle(self, handle: HANDLE) -> Optional[Callable[[], None]]:
        """
        Remove a Win32 handle from the event loop.
        Return either the registered handler or `None`.
        """
        if handle.value is None:
            return None  # Ignore.

        # Trigger remove events, so that the reader knows to stop.
        try:
            event = self._remove_events.pop(handle.value)
        except KeyError:
            pass
        else:
            windll.kernel32.SetEvent(event)

        try:
            return self._handle_callbacks.pop(handle.value)
        except KeyError:
            return None


@contextmanager
def attach_win32_input(input: _Win32InputBase, callback: Callable[[], None]):
    """
    Context manager that makes this input active in the current event loop.

    :param input: :class:`~prompt_toolkit.input.Input` object.
    :param input_ready_callback: Called when the input is ready to read.
    """
    win32_handles = input.win32_handles
    handle = input.handle

    if handle.value is None:
        raise ValueError("Invalid handle.")

    # Add reader.
    previous_callback = win32_handles.remove_win32_handle(handle)
    win32_handles.add_win32_handle(handle, callback)

    try:
        yield
    finally:
        win32_handles.remove_win32_handle(handle)

        if previous_callback:
            win32_handles.add_win32_handle(handle, previous_callback)


@contextmanager
def detach_win32_input(input: _Win32InputBase):
    win32_handles = input.win32_handles
    handle = input.handle

    if handle.value is None:
        raise ValueError("Invalid handle.")

    previous_callback = win32_handles.remove_win32_handle(handle)

    try:
        yield
    finally:
        if previous_callback:
            win32_handles.add_win32_handle(handle, previous_callback)


class raw_mode:
    """
    ::

        with raw_mode(stdin):
            ''' the windows terminal is now in 'raw' mode. '''

    The ``fileno`` attribute is ignored. This is to be compatible with the
    `raw_input` method of `.vt100_input`.
    """

    def __init__(self, fileno=None):
        self.handle = HANDLE(windll.kernel32.GetStdHandle(STD_INPUT_HANDLE))

    def __enter__(self):
        # Remember original mode.
        original_mode = DWORD()
        windll.kernel32.GetConsoleMode(self.handle, pointer(original_mode))
        self.original_mode = original_mode

        self._patch()

    def _patch(self) -> None:
        # Set raw
        ENABLE_ECHO_INPUT = 0x0004
        ENABLE_LINE_INPUT = 0x0002
        ENABLE_PROCESSED_INPUT = 0x0001

        windll.kernel32.SetConsoleMode(
            self.handle,
            self.original_mode.value
            & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT),
        )

    def __exit__(self, *a: object) -> None:
        # Restore original mode
        windll.kernel32.SetConsoleMode(self.handle, self.original_mode)


class cooked_mode(raw_mode):
    """
    ::

        with cooked_mode(stdin):
            ''' The pseudo-terminal stdin is now used in cooked mode. '''
    """

    def _patch(self) -> None:
        # Set cooked.
        ENABLE_ECHO_INPUT = 0x0004
        ENABLE_LINE_INPUT = 0x0002
        ENABLE_PROCESSED_INPUT = 0x0001

        windll.kernel32.SetConsoleMode(
            self.handle,
            self.original_mode.value
            | (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT),
        )
