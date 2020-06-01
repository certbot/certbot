from _curses import *  # noqa: F403
from _curses import _CursesWindow as _CursesWindow
from typing import TypeVar, Callable, Any

_T = TypeVar('_T')

# available after calling `curses.initscr()`
LINES: int
COLS: int

# available after calling `curses.start_color()`
COLORS: int
COLOR_PAIRS: int

def wrapper(func: Callable[..., _T], *arg: Any, **kwds: Any) -> _T: ...
