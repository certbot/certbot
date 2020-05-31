import sys
# Rename typing to _typing, as not to conflict with typing imported
# from _ast below when loaded in an unorthodox way by the Dropbox
# internal Bazel integration.
import typing as _typing
from typing import Any, Iterator, Optional, TypeVar, Union, overload

# The same unorthodox Bazel integration causes issues with sys, which
# is imported in both modules. unfortunately we can't just rename sys,
# since mypy only supports version checks with a sys that is named
# sys.
from _ast import *  # type: ignore

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

class NodeVisitor:
    def visit(self, node: AST) -> Any: ...
    def generic_visit(self, node: AST) -> Any: ...

class NodeTransformer(NodeVisitor):
    def generic_visit(self, node: AST) -> Optional[AST]: ...

_T = TypeVar("_T", bound=AST)

if sys.version_info >= (3, 8):
    @overload
    def parse(
        source: Union[str, bytes],
        filename: Union[str, bytes] = ...,
        mode: Literal["exec"] = ...,
        type_comments: bool = ...,
        feature_version: Union[None, int, _typing.Tuple[int, int]] = ...,
    ) -> Module: ...
    @overload
    def parse(
        source: Union[str, bytes],
        filename: Union[str, bytes] = ...,
        mode: str = ...,
        type_comments: bool = ...,
        feature_version: Union[None, int, _typing.Tuple[int, int]] = ...,
    ) -> AST: ...

else:
    @overload
    def parse(source: Union[str, bytes], filename: Union[str, bytes] = ..., mode: Literal["exec"] = ...) -> Module: ...
    @overload
    def parse(source: Union[str, bytes], filename: Union[str, bytes] = ..., mode: str = ...) -> AST: ...

def copy_location(new_node: _T, old_node: AST) -> _T: ...
def dump(node: AST, annotate_fields: bool = ..., include_attributes: bool = ...) -> str: ...
def fix_missing_locations(node: _T) -> _T: ...
def get_docstring(node: AST, clean: bool = ...) -> str: ...
def increment_lineno(node: _T, n: int = ...) -> _T: ...
def iter_child_nodes(node: AST) -> Iterator[AST]: ...
def iter_fields(node: AST) -> Iterator[_typing.Tuple[str, Any]]: ...
def literal_eval(node_or_string: Union[str, AST]) -> Any: ...
def get_source_segment(source: str, node: AST, *, padded: bool = ...) -> Optional[str]: ...
def walk(node: AST) -> Iterator[AST]: ...
