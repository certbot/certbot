import sys
from typing import Optional, TextIO, cast

from prompt_toolkit.patch_stdout import StdoutProxy
from prompt_toolkit.utils import (
    get_term_environment_variable,
    is_conemu_ansi,
    is_windows,
)

from .base import Output

__all__ = [
    "create_output",
]


def create_output(
    stdout: Optional[TextIO] = None, always_prefer_tty: bool = True
) -> Output:
    """
    Return an :class:`~prompt_toolkit.output.Output` instance for the command
    line.

    :param stdout: The stdout object
    :param always_prefer_tty: When set, look for `sys.stderr` if `sys.stdout`
        is not a TTY. (The prompt_toolkit render output is not meant to be
        consumed by something other then a terminal, so this is a reasonable
        default.)
    """
    if stdout is None:
        # By default, render to stdout. If the output is piped somewhere else,
        # render to stderr.
        stdout = sys.stdout

        if always_prefer_tty:
            for io in [sys.stdout, sys.stderr]:
                if io.isatty():
                    stdout = io
                    break

    # If the patch_stdout context manager has been used, then sys.stdout is
    # replaced by this proxy. For prompt_toolkit applications, we want to use
    # the real stdout.
    while isinstance(stdout, StdoutProxy):
        stdout = stdout.original_stdout

    if is_windows():
        from .conemu import ConEmuOutput
        from .win32 import Win32Output
        from .windows10 import is_win_vt100_enabled, Windows10_Output

        if is_win_vt100_enabled():
            return cast(Output, Windows10_Output(stdout))
        if is_conemu_ansi():
            return cast(Output, ConEmuOutput(stdout))
        else:
            return Win32Output(stdout)
    else:
        from .vt100 import Vt100_Output

        return Vt100_Output.from_pty(stdout, term=get_term_environment_variable())
