"""Provides Tab completion when prompting users for a path."""
import glob
from types import TracebackType
from typing import Callable
from typing import Iterator
from typing import Optional
from typing import Type
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Literal

# readline module is not available on all systems
try:
    import readline
except ImportError:
    import certbot._internal.display.dummy_readline as readline  # type: ignore


class Completer:
    """Provides Tab completion when prompting users for a path.

    This class is meant to be used with readline to provide Tab
    completion for users entering paths. The complete method can be
    passed to readline.set_completer directly, however, this function
    works best as a context manager. For example:

    with Completer():
        raw_input()

    In this example, Tab completion will be available during the call to
    raw_input above, however, readline will be restored to its previous
    state when exiting the body of the with statement.

    """

    def __init__(self) -> None:
        self._iter: Iterator[str]
        self._original_completer: Optional[Callable]
        self._original_delims: str

    def complete(self, text: str, state: int) -> Optional[str]:
        """Provides path completion for use with readline.

        :param str text: text to offer completions for
        :param int state: which completion to return

        :returns: possible completion for text or ``None`` if all
            completions have been returned
        :rtype: str

        """
        if state == 0:
            self._iter = glob.iglob(text + '*')
        return next(self._iter, None)

    def __enter__(self) -> None:
        self._original_completer = readline.get_completer()
        self._original_delims = readline.get_completer_delims()

        readline.set_completer(self.complete)
        readline.set_completer_delims(' \t\n;')

        # readline can be implemented using GNU readline, pyreadline or libedit
        # which have different configuration syntax
        if readline.__doc__ is not None and 'libedit' in readline.__doc__:
            readline.parse_and_bind('bind ^I rl_complete')
        else:
            readline.parse_and_bind('tab: complete')

    def __exit__(self, unused_type: Optional[Type[BaseException]],
                 unused_value: Optional[BaseException],
                 unused_traceback: Optional[TracebackType]) -> 'Literal[False]':
        readline.set_completer_delims(self._original_delims)
        readline.set_completer(self._original_completer)
        return False
