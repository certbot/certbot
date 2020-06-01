from typing import Callable, List, Union, Iterator, Tuple, Optional, Any, IO, NamedTuple, Dict

import sys
import types

from opcode import (hasconst as hasconst, hasname as hasname, hasjrel as hasjrel,
                    hasjabs as hasjabs, haslocal as haslocal, hascompare as hascompare,
                    hasfree as hasfree, cmp_op as cmp_op, opname as opname, opmap as opmap,
                    HAVE_ARGUMENT as HAVE_ARGUMENT, EXTENDED_ARG as EXTENDED_ARG)

if sys.version_info >= (3, 4):
    from opcode import stack_effect as stack_effect

if sys.version_info >= (3, 6):
    from opcode import hasnargs as hasnargs

# Strictly this should not have to include Callable, but mypy doesn't use FunctionType
# for functions (python/mypy#3171)
_have_code = Union[types.MethodType, types.FunctionType, types.CodeType, type, Callable[..., Any]]
_have_code_or_string = Union[_have_code, str, bytes]


if sys.version_info >= (3, 4):
    class Instruction(NamedTuple):
        opname: str
        opcode: int
        arg: Optional[int]
        argval: Any
        argrepr: str
        offset: int
        starts_line: Optional[int]
        is_jump_target: bool

    class Bytecode:
        codeobj: types.CodeType
        first_line: int
        def __init__(self, x: _have_code_or_string, *, first_line: Optional[int] = ...,
                     current_offset: Optional[int] = ...) -> None: ...
        def __iter__(self) -> Iterator[Instruction]: ...
        def __repr__(self) -> str: ...
        def info(self) -> str: ...
        def dis(self) -> str: ...

        @classmethod
        def from_traceback(cls, tb: types.TracebackType) -> Bytecode: ...


COMPILER_FLAG_NAMES: Dict[int, str]


def findlabels(code: _have_code) -> List[int]: ...
def findlinestarts(code: _have_code) -> Iterator[Tuple[int, int]]: ...

if sys.version_info >= (3, 0):
    def pretty_flags(flags: int) -> str: ...
    def code_info(x: _have_code_or_string) -> str: ...

if sys.version_info >= (3, 4):
    def dis(x: _have_code_or_string = ..., *, file: Optional[IO[str]] = ...) -> None: ...
    def distb(tb: Optional[types.TracebackType] = ..., *, file: Optional[IO[str]] = ...) -> None: ...
    def disassemble(co: _have_code, lasti: int = ..., *, file: Optional[IO[str]] = ...) -> None: ...
    def disco(co: _have_code, lasti: int = ..., *, file: Optional[IO[str]] = ...) -> None: ...
    def show_code(co: _have_code, *, file: Optional[IO[str]] = ...) -> None: ...

    def get_instructions(x: _have_code, *, first_line: Optional[int] = ...) -> Iterator[Instruction]: ...
else:
    def dis(x: _have_code_or_string = ...) -> None: ...
    def distb(tb: types.TracebackType = ...) -> None: ...
    def disassemble(co: _have_code, lasti: int = ...) -> None: ...
    def disco(co: _have_code, lasti: int = ...) -> None: ...

    if sys.version_info >= (3, 0):
        def show_code(co: _have_code) -> None: ...
