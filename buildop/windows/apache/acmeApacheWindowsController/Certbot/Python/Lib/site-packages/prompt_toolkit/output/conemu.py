from typing import Any, TextIO

from prompt_toolkit.data_structures import Size
from prompt_toolkit.renderer import Output

from .vt100 import Vt100_Output
from .win32 import Win32Output

__all__ = [
    "ConEmuOutput",
]


class ConEmuOutput:
    """
    ConEmu (Windows) output abstraction.

    ConEmu is a Windows console application, but it also supports ANSI escape
    sequences. This output class is actually a proxy to both `Win32Output` and
    `Vt100_Output`. It uses `Win32Output` for console sizing and scrolling, but
    all cursor movements and scrolling happens through the `Vt100_Output`.

    This way, we can have 256 colors in ConEmu and Cmder. Rendering will be
    even a little faster as well.

    http://conemu.github.io/
    http://gooseberrycreative.com/cmder/
    """

    def __init__(self, stdout: TextIO) -> None:
        self.win32_output = Win32Output(stdout)
        self.vt100_output = Vt100_Output(stdout, lambda: Size(0, 0))

    def __getattr__(self, name: str) -> Any:
        if name in (
            "get_size",
            "get_rows_below_cursor_position",
            "enable_mouse_support",
            "disable_mouse_support",
            "scroll_buffer_to_prompt",
            "get_win32_screen_buffer_info",
            "enable_bracketed_paste",
            "disable_bracketed_paste",
        ):
            return getattr(self.win32_output, name)
        else:
            return getattr(self.vt100_output, name)


Output.register(ConEmuOutput)
