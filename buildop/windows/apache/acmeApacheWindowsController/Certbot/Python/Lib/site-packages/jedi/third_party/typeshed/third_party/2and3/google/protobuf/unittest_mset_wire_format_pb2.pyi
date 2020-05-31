from google.protobuf.message import Message
from typing import Optional

class TestMessageSet(Message):
    def __init__(self,) -> None: ...

class TestMessageSetWireFormatContainer(Message):
    @property
    def message_set(self) -> TestMessageSet: ...
    def __init__(self, message_set: Optional[TestMessageSet] = ...) -> None: ...
