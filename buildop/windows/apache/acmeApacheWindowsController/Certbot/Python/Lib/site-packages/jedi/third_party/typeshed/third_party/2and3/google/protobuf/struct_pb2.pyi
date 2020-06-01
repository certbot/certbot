from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from google.protobuf.internal import well_known_types

from google.protobuf.message import Message
from typing import Iterable, List, Mapping, MutableMapping, Optional, Text, Tuple, cast

class NullValue(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> NullValue: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[NullValue]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, NullValue]]: ...

NULL_VALUE: NullValue

class Struct(Message, well_known_types.Struct):
    class FieldsEntry(Message):
        key: Text
        @property
        def value(self) -> Value: ...
        def __init__(self, key: Optional[Text] = ..., value: Optional[Value] = ...) -> None: ...
    @property
    def fields(self) -> MutableMapping[Text, Value]: ...
    def __init__(self, fields: Optional[Mapping[Text, Value]] = ...) -> None: ...

class _Value(Message):
    null_value: NullValue
    number_value: float
    string_value: Text
    bool_value: bool
    @property
    def struct_value(self) -> Struct: ...
    @property
    def list_value(self) -> ListValue: ...
    def __init__(
        self,
        null_value: Optional[NullValue] = ...,
        number_value: Optional[float] = ...,
        string_value: Optional[Text] = ...,
        bool_value: Optional[bool] = ...,
        struct_value: Optional[Struct] = ...,
        list_value: Optional[ListValue] = ...,
    ) -> None: ...

Value = _Value

class ListValue(Message, well_known_types.ListValue):
    @property
    def values(self) -> RepeatedCompositeFieldContainer[Value]: ...
    def __init__(self, values: Optional[Iterable[Value]] = ...) -> None: ...
