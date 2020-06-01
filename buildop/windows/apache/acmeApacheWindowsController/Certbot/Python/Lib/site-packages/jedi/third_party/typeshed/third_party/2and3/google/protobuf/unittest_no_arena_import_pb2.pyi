from google.protobuf.message import Message
from typing import Optional

class ImportNoArenaNestedMessage(Message):
    d: int
    def __init__(self, d: Optional[int] = ...) -> None: ...
