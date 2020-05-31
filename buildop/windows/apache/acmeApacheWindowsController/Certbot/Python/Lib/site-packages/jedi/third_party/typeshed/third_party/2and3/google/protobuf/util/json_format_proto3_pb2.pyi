from google.protobuf.any_pb2 import Any
from google.protobuf.duration_pb2 import Duration
from google.protobuf.field_mask_pb2 import FieldMask
from google.protobuf.internal.containers import RepeatedCompositeFieldContainer, RepeatedScalarFieldContainer
from google.protobuf.message import Message
from google.protobuf.struct_pb2 import ListValue, Struct, Value
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.unittest_pb2 import TestAllExtensions
from google.protobuf.wrappers_pb2 import (
    BoolValue,
    BytesValue,
    DoubleValue,
    FloatValue,
    Int32Value,
    Int64Value,
    StringValue,
    UInt32Value,
    UInt64Value,
)
from typing import Iterable, List, Mapping, MutableMapping, Optional, Text, Tuple, cast

class EnumType(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> EnumType: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[EnumType]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, EnumType]]: ...

FOO: EnumType
BAR: EnumType

class MessageType(Message):
    value: int
    def __init__(self, value: Optional[int] = ...) -> None: ...

class TestMessage(Message):
    bool_value: bool
    int32_value: int
    int64_value: int
    uint32_value: int
    uint64_value: int
    float_value: float
    double_value: float
    string_value: Text
    bytes_value: bytes
    enum_value: EnumType
    repeated_bool_value: RepeatedScalarFieldContainer[bool]
    repeated_int32_value: RepeatedScalarFieldContainer[int]
    repeated_int64_value: RepeatedScalarFieldContainer[int]
    repeated_uint32_value: RepeatedScalarFieldContainer[int]
    repeated_uint64_value: RepeatedScalarFieldContainer[int]
    repeated_float_value: RepeatedScalarFieldContainer[float]
    repeated_double_value: RepeatedScalarFieldContainer[float]
    repeated_string_value: RepeatedScalarFieldContainer[Text]
    repeated_bytes_value: RepeatedScalarFieldContainer[bytes]
    repeated_enum_value: RepeatedScalarFieldContainer[EnumType]
    @property
    def message_value(self) -> MessageType: ...
    @property
    def repeated_message_value(self) -> RepeatedCompositeFieldContainer[MessageType]: ...
    def __init__(
        self,
        bool_value: Optional[bool] = ...,
        int32_value: Optional[int] = ...,
        int64_value: Optional[int] = ...,
        uint32_value: Optional[int] = ...,
        uint64_value: Optional[int] = ...,
        float_value: Optional[float] = ...,
        double_value: Optional[float] = ...,
        string_value: Optional[Text] = ...,
        bytes_value: Optional[bytes] = ...,
        enum_value: Optional[EnumType] = ...,
        message_value: Optional[MessageType] = ...,
        repeated_bool_value: Optional[Iterable[bool]] = ...,
        repeated_int32_value: Optional[Iterable[int]] = ...,
        repeated_int64_value: Optional[Iterable[int]] = ...,
        repeated_uint32_value: Optional[Iterable[int]] = ...,
        repeated_uint64_value: Optional[Iterable[int]] = ...,
        repeated_float_value: Optional[Iterable[float]] = ...,
        repeated_double_value: Optional[Iterable[float]] = ...,
        repeated_string_value: Optional[Iterable[Text]] = ...,
        repeated_bytes_value: Optional[Iterable[bytes]] = ...,
        repeated_enum_value: Optional[Iterable[EnumType]] = ...,
        repeated_message_value: Optional[Iterable[MessageType]] = ...,
    ) -> None: ...

class TestOneof(Message):
    oneof_int32_value: int
    oneof_string_value: Text
    oneof_bytes_value: bytes
    oneof_enum_value: EnumType
    @property
    def oneof_message_value(self) -> MessageType: ...
    def __init__(
        self,
        oneof_int32_value: Optional[int] = ...,
        oneof_string_value: Optional[Text] = ...,
        oneof_bytes_value: Optional[bytes] = ...,
        oneof_enum_value: Optional[EnumType] = ...,
        oneof_message_value: Optional[MessageType] = ...,
    ) -> None: ...

class TestMap(Message):
    class BoolMapEntry(Message):
        key: bool
        value: int
        def __init__(self, key: Optional[bool] = ..., value: Optional[int] = ...) -> None: ...
    class Int32MapEntry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class Int64MapEntry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class Uint32MapEntry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class Uint64MapEntry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class StringMapEntry(Message):
        key: Text
        value: int
        def __init__(self, key: Optional[Text] = ..., value: Optional[int] = ...) -> None: ...
    @property
    def bool_map(self) -> MutableMapping[bool, int]: ...
    @property
    def int32_map(self) -> MutableMapping[int, int]: ...
    @property
    def int64_map(self) -> MutableMapping[int, int]: ...
    @property
    def uint32_map(self) -> MutableMapping[int, int]: ...
    @property
    def uint64_map(self) -> MutableMapping[int, int]: ...
    @property
    def string_map(self) -> MutableMapping[Text, int]: ...
    def __init__(
        self,
        bool_map: Optional[Mapping[bool, int]] = ...,
        int32_map: Optional[Mapping[int, int]] = ...,
        int64_map: Optional[Mapping[int, int]] = ...,
        uint32_map: Optional[Mapping[int, int]] = ...,
        uint64_map: Optional[Mapping[int, int]] = ...,
        string_map: Optional[Mapping[Text, int]] = ...,
    ) -> None: ...

class TestNestedMap(Message):
    class BoolMapEntry(Message):
        key: bool
        value: int
        def __init__(self, key: Optional[bool] = ..., value: Optional[int] = ...) -> None: ...
    class Int32MapEntry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class Int64MapEntry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class Uint32MapEntry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class Uint64MapEntry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class StringMapEntry(Message):
        key: Text
        value: int
        def __init__(self, key: Optional[Text] = ..., value: Optional[int] = ...) -> None: ...
    class MapMapEntry(Message):
        key: Text
        @property
        def value(self) -> TestNestedMap: ...
        def __init__(self, key: Optional[Text] = ..., value: Optional[TestNestedMap] = ...) -> None: ...
    @property
    def bool_map(self) -> MutableMapping[bool, int]: ...
    @property
    def int32_map(self) -> MutableMapping[int, int]: ...
    @property
    def int64_map(self) -> MutableMapping[int, int]: ...
    @property
    def uint32_map(self) -> MutableMapping[int, int]: ...
    @property
    def uint64_map(self) -> MutableMapping[int, int]: ...
    @property
    def string_map(self) -> MutableMapping[Text, int]: ...
    @property
    def map_map(self) -> MutableMapping[Text, TestNestedMap]: ...
    def __init__(
        self,
        bool_map: Optional[Mapping[bool, int]] = ...,
        int32_map: Optional[Mapping[int, int]] = ...,
        int64_map: Optional[Mapping[int, int]] = ...,
        uint32_map: Optional[Mapping[int, int]] = ...,
        uint64_map: Optional[Mapping[int, int]] = ...,
        string_map: Optional[Mapping[Text, int]] = ...,
        map_map: Optional[Mapping[Text, TestNestedMap]] = ...,
    ) -> None: ...

class TestWrapper(Message):
    @property
    def bool_value(self) -> BoolValue: ...
    @property
    def int32_value(self) -> Int32Value: ...
    @property
    def int64_value(self) -> Int64Value: ...
    @property
    def uint32_value(self) -> UInt32Value: ...
    @property
    def uint64_value(self) -> UInt64Value: ...
    @property
    def float_value(self) -> FloatValue: ...
    @property
    def double_value(self) -> DoubleValue: ...
    @property
    def string_value(self) -> StringValue: ...
    @property
    def bytes_value(self) -> BytesValue: ...
    @property
    def repeated_bool_value(self) -> RepeatedCompositeFieldContainer[BoolValue]: ...
    @property
    def repeated_int32_value(self) -> RepeatedCompositeFieldContainer[Int32Value]: ...
    @property
    def repeated_int64_value(self) -> RepeatedCompositeFieldContainer[Int64Value]: ...
    @property
    def repeated_uint32_value(self) -> RepeatedCompositeFieldContainer[UInt32Value]: ...
    @property
    def repeated_uint64_value(self) -> RepeatedCompositeFieldContainer[UInt64Value]: ...
    @property
    def repeated_float_value(self) -> RepeatedCompositeFieldContainer[FloatValue]: ...
    @property
    def repeated_double_value(self) -> RepeatedCompositeFieldContainer[DoubleValue]: ...
    @property
    def repeated_string_value(self) -> RepeatedCompositeFieldContainer[StringValue]: ...
    @property
    def repeated_bytes_value(self) -> RepeatedCompositeFieldContainer[BytesValue]: ...
    def __init__(
        self,
        bool_value: Optional[BoolValue] = ...,
        int32_value: Optional[Int32Value] = ...,
        int64_value: Optional[Int64Value] = ...,
        uint32_value: Optional[UInt32Value] = ...,
        uint64_value: Optional[UInt64Value] = ...,
        float_value: Optional[FloatValue] = ...,
        double_value: Optional[DoubleValue] = ...,
        string_value: Optional[StringValue] = ...,
        bytes_value: Optional[BytesValue] = ...,
        repeated_bool_value: Optional[Iterable[BoolValue]] = ...,
        repeated_int32_value: Optional[Iterable[Int32Value]] = ...,
        repeated_int64_value: Optional[Iterable[Int64Value]] = ...,
        repeated_uint32_value: Optional[Iterable[UInt32Value]] = ...,
        repeated_uint64_value: Optional[Iterable[UInt64Value]] = ...,
        repeated_float_value: Optional[Iterable[FloatValue]] = ...,
        repeated_double_value: Optional[Iterable[DoubleValue]] = ...,
        repeated_string_value: Optional[Iterable[StringValue]] = ...,
        repeated_bytes_value: Optional[Iterable[BytesValue]] = ...,
    ) -> None: ...

class TestTimestamp(Message):
    @property
    def value(self) -> Timestamp: ...
    @property
    def repeated_value(self) -> RepeatedCompositeFieldContainer[Timestamp]: ...
    def __init__(self, value: Optional[Timestamp] = ..., repeated_value: Optional[Iterable[Timestamp]] = ...) -> None: ...

class TestDuration(Message):
    @property
    def value(self) -> Duration: ...
    @property
    def repeated_value(self) -> RepeatedCompositeFieldContainer[Duration]: ...
    def __init__(self, value: Optional[Duration] = ..., repeated_value: Optional[Iterable[Duration]] = ...) -> None: ...

class TestFieldMask(Message):
    @property
    def value(self) -> FieldMask: ...
    def __init__(self, value: Optional[FieldMask] = ...) -> None: ...

class TestStruct(Message):
    @property
    def value(self) -> Struct: ...
    @property
    def repeated_value(self) -> RepeatedCompositeFieldContainer[Struct]: ...
    def __init__(self, value: Optional[Struct] = ..., repeated_value: Optional[Iterable[Struct]] = ...) -> None: ...

class TestAny(Message):
    @property
    def value(self) -> Any: ...
    @property
    def repeated_value(self) -> RepeatedCompositeFieldContainer[Any]: ...
    def __init__(self, value: Optional[Any] = ..., repeated_value: Optional[Iterable[Any]] = ...) -> None: ...

class TestValue(Message):
    @property
    def value(self) -> Value: ...
    @property
    def repeated_value(self) -> RepeatedCompositeFieldContainer[Value]: ...
    def __init__(self, value: Optional[Value] = ..., repeated_value: Optional[Iterable[Value]] = ...) -> None: ...

class TestListValue(Message):
    @property
    def value(self) -> ListValue: ...
    @property
    def repeated_value(self) -> RepeatedCompositeFieldContainer[ListValue]: ...
    def __init__(self, value: Optional[ListValue] = ..., repeated_value: Optional[Iterable[ListValue]] = ...) -> None: ...

class TestBoolValue(Message):
    class BoolMapEntry(Message):
        key: bool
        value: int
        def __init__(self, key: Optional[bool] = ..., value: Optional[int] = ...) -> None: ...
    bool_value: bool
    @property
    def bool_map(self) -> MutableMapping[bool, int]: ...
    def __init__(self, bool_value: Optional[bool] = ..., bool_map: Optional[Mapping[bool, int]] = ...) -> None: ...

class TestCustomJsonName(Message):
    value: int
    def __init__(self, value: Optional[int] = ...) -> None: ...

class TestExtensions(Message):
    @property
    def extensions(self) -> TestAllExtensions: ...
    def __init__(self, extensions: Optional[TestAllExtensions] = ...) -> None: ...

class TestEnumValue(Message):
    enum_value1: EnumType
    enum_value2: EnumType
    enum_value3: EnumType
    def __init__(
        self, enum_value1: Optional[EnumType] = ..., enum_value2: Optional[EnumType] = ..., enum_value3: Optional[EnumType] = ...
    ) -> None: ...
