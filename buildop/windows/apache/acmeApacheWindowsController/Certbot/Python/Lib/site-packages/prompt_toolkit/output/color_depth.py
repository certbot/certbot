import os
from enum import Enum
from typing import Optional

from prompt_toolkit.utils import is_dumb_terminal, is_windows

__all__ = [
    "ColorDepth",
]


class ColorDepth(str, Enum):
    """
    Possible color depth values for the output.
    """

    value: str

    #: One color only.
    DEPTH_1_BIT = "DEPTH_1_BIT"

    #: ANSI Colors.
    DEPTH_4_BIT = "DEPTH_4_BIT"

    #: The default.
    DEPTH_8_BIT = "DEPTH_8_BIT"

    #: 24 bit True color.
    DEPTH_24_BIT = "DEPTH_24_BIT"

    # Aliases.
    MONOCHROME = DEPTH_1_BIT
    ANSI_COLORS_ONLY = DEPTH_4_BIT
    DEFAULT = DEPTH_8_BIT
    TRUE_COLOR = DEPTH_24_BIT

    @classmethod
    def default(cls, term: Optional[str] = None) -> "ColorDepth":
        """
        Return the default color depth, according to the $TERM value.

        We prefer 256 colors almost always, because this is what most terminals
        support these days, and is a good default.

        The $PROMPT_TOOLKIT_COLOR_DEPTH environment variable can be used to
        override this outcome. This is a way to enforce a certain color depth
        in all prompt_toolkit applications.

        If no `term` parameter is given, we use the $TERM environment variable.
        """
        # Take `TERM` value from environment variable if nothing was passed.
        if term is None:
            term = os.environ.get("TERM", "")

        if is_dumb_terminal(term):
            return cls.DEPTH_1_BIT

        if term in ("linux", "eterm-color"):
            return cls.DEPTH_4_BIT

        # For now, always use 4 bit color on Windows 10 by default, even when
        # vt100 escape sequences with ENABLE_VIRTUAL_TERMINAL_PROCESSING are
        # supported. We don't have a reliable way yet to know whether our
        # console supports true color or only 4-bit.
        if is_windows() and "PROMPT_TOOLKIT_COLOR_DEPTH" not in os.environ:
            return cls.DEPTH_4_BIT

        # Check the `PROMPT_TOOLKIT_COLOR_DEPTH` environment variable.
        all_values = [i.value for i in ColorDepth]

        if os.environ.get("PROMPT_TOOLKIT_COLOR_DEPTH") in all_values:
            return cls(os.environ["PROMPT_TOOLKIT_COLOR_DEPTH"])

        return cls.DEPTH_8_BIT
