from google.protobuf.any_pb2 import Any
from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from google.protobuf.message import Message
from typing import Iterable, Optional

class TestAny(Message):
    int32_value: int
    @property
    def any_value(self) -> Any: ...
    @property
    def repeated_any_value(self) -> RepeatedCompositeFieldContainer[Any]: ...
    def __init__(
        self, int32_value: Optional[int] = ..., any_value: Optional[Any] = ..., repeated_any_value: Optional[Iterable[Any]] = ...
    ) -> None: ...
