from google.protobuf.message import Message
from typing import List, Optional, Tuple, cast

class TestEnum(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> TestEnum: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[TestEnum]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, TestEnum]]: ...

FOO: TestEnum

class TestMessage(Message):
    a: int
    def __init__(self, a: Optional[int] = ...) -> None: ...
