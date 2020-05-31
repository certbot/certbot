# Stubs for email (Python 3.4)

from typing import Callable, IO
from email.message import Message
from email.policy import Policy

def message_from_string(s: str, _class: Callable[[], Message] = ..., *, policy: Policy = ...) -> Message: ...
def message_from_bytes(s: bytes, _class: Callable[[], Message] = ..., *, policy: Policy = ...) -> Message: ...
def message_from_file(fp: IO[str], _class: Callable[[], Message] = ..., *, policy: Policy = ...) -> Message: ...
def message_from_binary_file(fp: IO[bytes], _class: Callable[[], Message] = ..., *, policy: Policy = ...) -> Message: ...

# Names in __all__ with no definition:
#   base64mime
#   charset
#   encoders
#   errors
#   feedparser
#   generator
#   header
#   iterators
#   message
#   mime
#   parser
#   quoprimime
#   utils
