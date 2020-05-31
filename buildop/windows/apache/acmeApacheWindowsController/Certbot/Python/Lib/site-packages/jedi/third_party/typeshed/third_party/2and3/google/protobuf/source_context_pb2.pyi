from google.protobuf.message import Message
from typing import Optional, Text

class SourceContext(Message):
    file_name: Text
    def __init__(self, file_name: Optional[Text] = ...) -> None: ...
