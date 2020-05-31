from typing import Generator, List, Optional

from prompt_toolkit.output.vt100 import BG_ANSI_COLORS, FG_ANSI_COLORS
from prompt_toolkit.output.vt100 import _256_colors as _256_colors_table

from .base import StyleAndTextTuples

__all__ = [
    "ANSI",
    "ansi_escape",
]


class ANSI:
    """
    ANSI formatted text.
    Take something ANSI escaped text, for use as a formatted string. E.g.

    ::

        ANSI('\\x1b[31mhello \\x1b[32mworld')

    Characters between ``\\001`` and ``\\002`` are supposed to have a zero width
    when printed, but these are literally sent to the terminal output. This can
    be used for instance, for inserting Final Term prompt commands.  They will
    be translated into a prompt_toolkit '[ZeroWidthEscape]' fragment.
    """

    def __init__(self, value: str) -> None:
        self.value = value
        self._formatted_text: StyleAndTextTuples = []

        # Default style attributes.
        self._color: Optional[str] = None
        self._bgcolor: Optional[str] = None
        self._bold = False
        self._underline = False
        self._italic = False
        self._blink = False
        self._reverse = False
        self._hidden = False

        # Process received text.
        parser = self._parse_corot()
        parser.send(None)  # type: ignore
        for c in value:
            parser.send(c)

    def _parse_corot(self) -> Generator[None, str, None]:
        """
        Coroutine that parses the ANSI escape sequences.
        """
        style = ""
        formatted_text = self._formatted_text

        while True:
            csi = False
            c = yield

            # Everything between \001 and \002 should become a ZeroWidthEscape.
            if c == "\001":
                escaped_text = ""
                while c != "\002":
                    c = yield
                    if c == "\002":
                        formatted_text.append(("[ZeroWidthEscape]", escaped_text))
                        c = yield
                        break
                    else:
                        escaped_text += c

            if c == "\x1b":
                # Start of color escape sequence.
                square_bracket = yield
                if square_bracket == "[":
                    csi = True
                else:
                    continue
            elif c == "\x9b":
                csi = True

            if csi:
                # Got a CSI sequence. Color codes are following.
                current = ""
                params = []
                while True:
                    char = yield
                    if char.isdigit():
                        current += char
                    else:
                        params.append(min(int(current or 0), 9999))
                        if char == ";":
                            current = ""
                        elif char == "m":
                            # Set attributes and token.
                            self._select_graphic_rendition(params)
                            style = self._create_style_string()
                            break
                        else:
                            # Ignore unsupported sequence.
                            break
            else:
                # Add current character.
                # NOTE: At this point, we could merge the current character
                #       into the previous tuple if the style did not change,
                #       however, it's not worth the effort given that it will
                #       be "Exploded" once again when it's rendered to the
                #       output.
                formatted_text.append((style, c))

    def _select_graphic_rendition(self, attrs: List[int]) -> None:
        """
        Taken a list of graphics attributes and apply changes.
        """
        if not attrs:
            attrs = [0]
        else:
            attrs = list(attrs[::-1])

        while attrs:
            attr = attrs.pop()

            if attr in _fg_colors:
                self._color = _fg_colors[attr]
            elif attr in _bg_colors:
                self._bgcolor = _bg_colors[attr]
            elif attr == 1:
                self._bold = True
            elif attr == 3:
                self._italic = True
            elif attr == 4:
                self._underline = True
            elif attr == 5:
                self._blink = True
            elif attr == 6:
                self._blink = True  # Fast blink.
            elif attr == 7:
                self._reverse = True
            elif attr == 8:
                self._hidden = True
            elif attr == 22:
                self._bold = False
            elif attr == 23:
                self._italic = False
            elif attr == 24:
                self._underline = False
            elif attr == 25:
                self._blink = False
            elif attr == 27:
                self._reverse = False
            elif not attr:
                self._color = None
                self._bgcolor = None
                self._bold = False
                self._underline = False
                self._italic = False
                self._blink = False
                self._reverse = False
                self._hidden = False

            elif attr in (38, 48) and len(attrs) > 1:
                n = attrs.pop()

                # 256 colors.
                if n == 5 and len(attrs) >= 1:
                    if attr == 38:
                        m = attrs.pop()
                        self._color = _256_colors.get(m)
                    elif attr == 48:
                        m = attrs.pop()
                        self._bgcolor = _256_colors.get(m)

                # True colors.
                if n == 2 and len(attrs) >= 3:
                    try:
                        color_str = "#%02x%02x%02x" % (
                            attrs.pop(),
                            attrs.pop(),
                            attrs.pop(),
                        )
                    except IndexError:
                        pass
                    else:
                        if attr == 38:
                            self._color = color_str
                        elif attr == 48:
                            self._bgcolor = color_str

    def _create_style_string(self) -> str:
        """
        Turn current style flags into a string for usage in a formatted text.
        """
        result = []
        if self._color:
            result.append(self._color)
        if self._bgcolor:
            result.append("bg:" + self._bgcolor)
        if self._bold:
            result.append("bold")
        if self._underline:
            result.append("underline")
        if self._italic:
            result.append("italic")
        if self._blink:
            result.append("blink")
        if self._reverse:
            result.append("reverse")
        if self._hidden:
            result.append("hidden")

        return " ".join(result)

    def __repr__(self) -> str:
        return "ANSI(%r)" % (self.value,)

    def __pt_formatted_text__(self) -> StyleAndTextTuples:
        return self._formatted_text

    def format(self, *args: str, **kwargs: str) -> "ANSI":
        """
        Like `str.format`, but make sure that the arguments are properly
        escaped. (No ANSI escapes can be injected.)
        """
        # Escape all the arguments.
        args = tuple(ansi_escape(a) for a in args)
        kwargs = {k: ansi_escape(v) for k, v in kwargs.items()}

        return ANSI(self.value.format(*args, **kwargs))


# Mapping of the ANSI color codes to their names.
_fg_colors = {v: k for k, v in FG_ANSI_COLORS.items()}
_bg_colors = {v: k for k, v in BG_ANSI_COLORS.items()}

# Mapping of the escape codes for 256colors to their 'ffffff' value.
_256_colors = {}

for i, (r, g, b) in enumerate(_256_colors_table.colors):
    _256_colors[i] = "#%02x%02x%02x" % (r, g, b)


def ansi_escape(text: str) -> str:
    """
    Replace characters with a special meaning.
    """
    return text.replace("\x1b", "?").replace("\b", "?")
