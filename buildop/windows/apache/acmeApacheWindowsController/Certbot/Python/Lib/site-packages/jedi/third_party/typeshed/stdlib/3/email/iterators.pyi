# Stubs for email.iterators (Python 3.4)

from typing import Iterator, Optional
from email.message import Message

def body_line_iterator(msg: Message, decode: bool = ...) -> Iterator[str]: ...
def typed_subpart_iterator(msg: Message, maintype: str = ...,
                           subtype: Optional[str] = ...) -> Iterator[str]: ...
