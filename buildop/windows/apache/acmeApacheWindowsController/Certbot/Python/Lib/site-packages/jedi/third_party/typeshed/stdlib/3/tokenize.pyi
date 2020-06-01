from typing import Any, Callable, Generator, Iterable, List, NamedTuple, Optional, Union, Sequence, TextIO, Tuple
from builtins import open as _builtin_open
import sys
from token import *  # noqa: F403

if sys.version_info < (3, 7):
    COMMENT: int
    NL: int
    ENCODING: int

_Position = Tuple[int, int]

class _TokenInfo(NamedTuple):
    type: int
    string: str
    start: _Position
    end: _Position
    line: str

class TokenInfo(_TokenInfo):
    @property
    def exact_type(self) -> int: ...

# Backwards compatible tokens can be sequences of a shorter length too
_Token = Union[TokenInfo, Sequence[Union[int, str, _Position]]]

class TokenError(Exception): ...
class StopTokenizing(Exception): ...

class Untokenizer:
    tokens: List[str]
    prev_row: int
    prev_col: int
    encoding: Optional[str]
    def __init__(self) -> None: ...
    def add_whitespace(self, start: _Position) -> None: ...
    def untokenize(self, iterable: Iterable[_Token]) -> str: ...
    def compat(self, token: Sequence[Union[int, str]], iterable: Iterable[_Token]) -> None: ...

def untokenize(iterable: Iterable[_Token]) -> Any: ...
def detect_encoding(readline: Callable[[], bytes]) -> Tuple[str, Sequence[bytes]]: ...
def tokenize(readline: Callable[[], bytes]) -> Generator[TokenInfo, None, None]: ...
def generate_tokens(readline: Callable[[], str]) -> Generator[TokenInfo, None, None]: ...  # undocumented

if sys.version_info >= (3, 6):
    from os import PathLike
    def open(filename: Union[str, bytes, int, PathLike[Any]]) -> TextIO: ...
else:
    def open(filename: Union[str, bytes, int]) -> TextIO: ...

# Names in __all__ with no definition:
#   AMPER
#   AMPEREQUAL
#   ASYNC
#   AT
#   ATEQUAL
#   AWAIT
#   CIRCUMFLEX
#   CIRCUMFLEXEQUAL
#   COLON
#   COMMA
#   DEDENT
#   DOT
#   DOUBLESLASH
#   DOUBLESLASHEQUAL
#   DOUBLESTAR
#   DOUBLESTAREQUAL
#   ELLIPSIS
#   ENDMARKER
#   EQEQUAL
#   EQUAL
#   ERRORTOKEN
#   GREATER
#   GREATEREQUAL
#   INDENT
#   ISEOF
#   ISNONTERMINAL
#   ISTERMINAL
#   LBRACE
#   LEFTSHIFT
#   LEFTSHIFTEQUAL
#   LESS
#   LESSEQUAL
#   LPAR
#   LSQB
#   MINEQUAL
#   MINUS
#   NAME
#   NEWLINE
#   NOTEQUAL
#   NT_OFFSET
#   NUMBER
#   N_TOKENS
#   OP
#   PERCENT
#   PERCENTEQUAL
#   PLUS
#   PLUSEQUAL
#   RARROW
#   RBRACE
#   RIGHTSHIFT
#   RIGHTSHIFTEQUAL
#   RPAR
#   RSQB
#   SEMI
#   SLASH
#   SLASHEQUAL
#   STAR
#   STAREQUAL
#   STRING
#   TILDE
#   VBAR
#   VBAREQUAL
#   tok_name
