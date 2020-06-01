from prompt_toolkit.data_structures import Point
from prompt_toolkit.key_binding.key_processor import KeyPress, KeyPressEvent
from prompt_toolkit.keys import Keys
from prompt_toolkit.mouse_events import MouseEvent, MouseEventType
from prompt_toolkit.utils import is_windows

from ..key_bindings import KeyBindings

__all__ = [
    "load_mouse_bindings",
]

E = KeyPressEvent


def load_mouse_bindings() -> KeyBindings:
    """
    Key bindings, required for mouse support.
    (Mouse events enter through the key binding system.)
    """
    key_bindings = KeyBindings()

    @key_bindings.add(Keys.Vt100MouseEvent)
    def _(event: E) -> None:
        """
        Handling of incoming mouse event.
        """
        # TypicaL:   "eSC[MaB*"
        # Urxvt:     "Esc[96;14;13M"
        # Xterm SGR: "Esc[<64;85;12M"

        # Parse incoming packet.
        if event.data[2] == "M":
            # Typical.
            mouse_event, x, y = map(ord, event.data[3:])
            mouse_event_type = {
                32: MouseEventType.MOUSE_DOWN,
                35: MouseEventType.MOUSE_UP,
                96: MouseEventType.SCROLL_UP,
                97: MouseEventType.SCROLL_DOWN,
            }.get(mouse_event)

            # Handle situations where `PosixStdinReader` used surrogateescapes.
            if x >= 0xDC00:
                x -= 0xDC00
            if y >= 0xDC00:
                y -= 0xDC00

            x -= 32
            y -= 32
        else:
            # Urxvt and Xterm SGR.
            # When the '<' is not present, we are not using the Xterm SGR mode,
            # but Urxvt instead.
            data = event.data[2:]
            if data[:1] == "<":
                sgr = True
                data = data[1:]
            else:
                sgr = False

            # Extract coordinates.
            mouse_event, x, y = map(int, data[:-1].split(";"))
            m = data[-1]

            # Parse event type.
            if sgr:
                mouse_event_type = {
                    (0, "M"): MouseEventType.MOUSE_DOWN,
                    (0, "m"): MouseEventType.MOUSE_UP,
                    (64, "M"): MouseEventType.SCROLL_UP,
                    (65, "M"): MouseEventType.SCROLL_DOWN,
                }.get((mouse_event, m))
            else:
                mouse_event_type = {
                    32: MouseEventType.MOUSE_DOWN,
                    35: MouseEventType.MOUSE_UP,
                    96: MouseEventType.SCROLL_UP,
                    97: MouseEventType.SCROLL_DOWN,
                }.get(mouse_event)

        x -= 1
        y -= 1

        # Only handle mouse events when we know the window height.
        if event.app.renderer.height_is_known and mouse_event_type is not None:
            # Take region above the layout into account. The reported
            # coordinates are absolute to the visible part of the terminal.
            from prompt_toolkit.renderer import HeightIsUnknownError

            try:
                y -= event.app.renderer.rows_above_layout
            except HeightIsUnknownError:
                return

            # Call the mouse handler from the renderer.
            handler = event.app.renderer.mouse_handlers.mouse_handlers[x, y]
            handler(MouseEvent(position=Point(x=x, y=y), event_type=mouse_event_type))

    @key_bindings.add(Keys.ScrollUp)
    def _scroll_up(event: E) -> None:
        """
        Scroll up event without cursor position.
        """
        # We don't receive a cursor position, so we don't know which window to
        # scroll. Just send an 'up' key press instead.
        event.key_processor.feed(KeyPress(Keys.Up), first=True)

    @key_bindings.add(Keys.ScrollDown)
    def _scroll_down(event: E) -> None:
        """
        Scroll down event without cursor position.
        """
        event.key_processor.feed(KeyPress(Keys.Down), first=True)

    @key_bindings.add(Keys.WindowsMouseEvent)
    def _mouse(event: E) -> None:
        """
        Handling of mouse events for Windows.
        """
        assert is_windows()  # This key binding should only exist for Windows.

        # Parse data.
        pieces = event.data.split(";")

        event_type = MouseEventType(pieces[0])
        x = int(pieces[1])
        y = int(pieces[2])

        # Make coordinates absolute to the visible part of the terminal.
        output = event.app.renderer.output

        from prompt_toolkit.output.win32 import Win32Output

        if isinstance(output, Win32Output):
            screen_buffer_info = output.get_win32_screen_buffer_info()
            rows_above_cursor = (
                screen_buffer_info.dwCursorPosition.Y - event.app.renderer._cursor_pos.y
            )
            y -= rows_above_cursor

            # Call the mouse event handler.
            handler = event.app.renderer.mouse_handlers.mouse_handlers[x, y]
            handler(MouseEvent(position=Point(x=x, y=y), event_type=event_type))

    return key_bindings
