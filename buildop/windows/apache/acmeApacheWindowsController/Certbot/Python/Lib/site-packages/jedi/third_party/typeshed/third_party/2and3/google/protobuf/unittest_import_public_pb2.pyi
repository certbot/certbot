from google.protobuf.message import Message
from typing import Optional

class PublicImportMessage(Message):
    e: int
    def __init__(self, e: Optional[int] = ...) -> None: ...
