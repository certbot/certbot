from google.protobuf.internal.containers import RepeatedScalarFieldContainer
from google.protobuf.internal import well_known_types

from google.protobuf.message import Message
from typing import Iterable, Optional, Text

class FieldMask(Message, well_known_types.FieldMask):
    paths: RepeatedScalarFieldContainer[Text]
    def __init__(self, paths: Optional[Iterable[Text]] = ...) -> None: ...
