from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from google.protobuf.message import Message
from google.protobuf.unittest_no_arena_import_pb2 import ImportNoArenaNestedMessage
from typing import Iterable, Optional

class NestedMessage(Message):
    d: int
    def __init__(self, d: Optional[int] = ...) -> None: ...

class ArenaMessage(Message):
    @property
    def repeated_nested_message(self) -> RepeatedCompositeFieldContainer[NestedMessage]: ...
    @property
    def repeated_import_no_arena_message(self) -> RepeatedCompositeFieldContainer[ImportNoArenaNestedMessage]: ...
    def __init__(
        self,
        repeated_nested_message: Optional[Iterable[NestedMessage]] = ...,
        repeated_import_no_arena_message: Optional[Iterable[ImportNoArenaNestedMessage]] = ...,
    ) -> None: ...
