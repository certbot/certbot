from asyncio import get_event_loop
from typing import TYPE_CHECKING, Any, Optional, TextIO

from prompt_toolkit.application import Application
from prompt_toolkit.application.current import get_app_session
from prompt_toolkit.formatted_text import (
    FormattedText,
    StyleAndTextTuples,
    to_formatted_text,
)
from prompt_toolkit.input import DummyInput
from prompt_toolkit.layout import Layout
from prompt_toolkit.output import ColorDepth, Output
from prompt_toolkit.output.defaults import create_output
from prompt_toolkit.renderer import (
    print_formatted_text as renderer_print_formatted_text,
)
from prompt_toolkit.styles import (
    BaseStyle,
    StyleTransformation,
    default_pygments_style,
    default_ui_style,
    merge_styles,
)

if TYPE_CHECKING:
    from prompt_toolkit.layout.containers import Container

__all__ = [
    "print_formatted_text",
    "print_container",
    "clear",
    "set_title",
    "clear_title",
]


def print_formatted_text(
    *values: Any,
    sep: str = " ",
    end: str = "\n",
    file: Optional[TextIO] = None,
    flush: bool = False,
    style: Optional[BaseStyle] = None,
    output: Optional[Output] = None,
    color_depth: Optional[ColorDepth] = None,
    style_transformation: Optional[StyleTransformation] = None,
    include_default_pygments_style: bool = True,
) -> None:
    """
    ::

        print_formatted_text(*values, sep=' ', end='\\n', file=None, flush=False, style=None, output=None)

    Print text to stdout. This is supposed to be compatible with Python's print
    function, but supports printing of formatted text. You can pass a
    :class:`~prompt_toolkit.formatted_text.FormattedText`,
    :class:`~prompt_toolkit.formatted_text.HTML` or
    :class:`~prompt_toolkit.formatted_text.ANSI` object to print formatted
    text.

    * Print HTML as follows::

        print_formatted_text(HTML('<i>Some italic text</i> <ansired>This is red!</ansired>'))

        style = Style.from_dict({
            'hello': '#ff0066',
            'world': '#884444 italic',
        })
        print_formatted_text(HTML('<hello>Hello</hello> <world>world</world>!'), style=style)

    * Print a list of (style_str, text) tuples in the given style to the
      output.  E.g.::

        style = Style.from_dict({
            'hello': '#ff0066',
            'world': '#884444 italic',
        })
        fragments = FormattedText([
            ('class:hello', 'Hello'),
            ('class:world', 'World'),
        ])
        print_formatted_text(fragments, style=style)

    If you want to print a list of Pygments tokens, wrap it in
    :class:`~prompt_toolkit.formatted_text.PygmentsTokens` to do the
    conversion.

    :param values: Any kind of printable object, or formatted string.
    :param sep: String inserted between values, default a space.
    :param end: String appended after the last value, default a newline.
    :param style: :class:`.Style` instance for the color scheme.
    :param include_default_pygments_style: `bool`. Include the default Pygments
        style when set to `True` (the default).
    """
    assert not (output and file)

    # Build/merge style.
    styles = [default_ui_style()]
    if include_default_pygments_style:
        styles.append(default_pygments_style())
    if style:
        styles.append(style)

    merged_style = merge_styles(styles)

    # Create Output object.
    if output is None:
        if file:
            output = create_output(stdout=file)
        else:
            output = get_app_session().output

    assert isinstance(output, Output)

    # Get color depth.
    color_depth = color_depth or ColorDepth.default()

    # Merges values.
    def to_text(val: Any) -> StyleAndTextTuples:
        # Normal lists which are not instances of `FormattedText` are
        # considered plain text.
        if isinstance(val, list) and not isinstance(val, FormattedText):
            return to_formatted_text("{0}".format(val))
        return to_formatted_text(val, auto_convert=True)

    fragments = []
    for i, value in enumerate(values):
        fragments.extend(to_text(value))

        if sep and i != len(values) - 1:
            fragments.extend(to_text(sep))

    fragments.extend(to_text(end))

    # Print output.
    renderer_print_formatted_text(
        output,
        fragments,
        merged_style,
        color_depth=color_depth,
        style_transformation=style_transformation,
    )

    # Flush the output stream.
    if flush:
        output.flush()


def print_container(container: "Container", file: Optional[TextIO] = None) -> None:
    """
    Print any layout to the output in a non-interactive way.

    Example usage::

        from prompt_toolkit.widgets import Frame, TextArea
        print_container(
            Frame(TextArea(text='Hello world!')))
    """
    if file:
        output = create_output(stdout=file)
    else:
        output = get_app_session().output

    def exit_immediately() -> None:
        # Use `call_from_executor` to exit "soon", so that we still render one
        # initial time, before exiting the application.
        get_event_loop().call_soon(lambda: app.exit())

    app: Application[None] = Application(
        layout=Layout(container=container), output=output, input=DummyInput()
    )
    app.run(pre_run=exit_immediately)


def clear() -> None:
    """
    Clear the screen.
    """
    output = get_app_session().output
    output.erase_screen()
    output.cursor_goto(0, 0)
    output.flush()


def set_title(text: str) -> None:
    """
    Set the terminal title.
    """
    output = get_app_session().output
    output.set_title(text)


def clear_title() -> None:
    """
    Erase the current title.
    """
    set_title("")
