from google.protobuf.message import Message
from typing import List, Optional, Tuple, cast

class ImportEnum(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> ImportEnum: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[ImportEnum]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, ImportEnum]]: ...

IMPORT_FOO: ImportEnum
IMPORT_BAR: ImportEnum
IMPORT_BAZ: ImportEnum

class ImportEnumForMap(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> ImportEnumForMap: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[ImportEnumForMap]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, ImportEnumForMap]]: ...

UNKNOWN: ImportEnumForMap
FOO: ImportEnumForMap
BAR: ImportEnumForMap

class ImportMessage(Message):
    d: int
    def __init__(self, d: Optional[int] = ...) -> None: ...
