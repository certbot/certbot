from google.protobuf.internal.containers import RepeatedCompositeFieldContainer, RepeatedScalarFieldContainer
from google.protobuf.message import Message
import builtins
from typing import Iterable, List, Mapping, MutableMapping, Optional, Text, Tuple, cast

class ForeignEnumProto2(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> ForeignEnumProto2: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[ForeignEnumProto2]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, ForeignEnumProto2]]: ...

FOREIGN_FOO: ForeignEnumProto2
FOREIGN_BAR: ForeignEnumProto2
FOREIGN_BAZ: ForeignEnumProto2

class TestAllTypesProto2(Message):
    class NestedEnum(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> TestAllTypesProto2.NestedEnum: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[TestAllTypesProto2.NestedEnum]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, TestAllTypesProto2.NestedEnum]]: ...
    FOO: TestAllTypesProto2.NestedEnum
    BAR: TestAllTypesProto2.NestedEnum
    BAZ: TestAllTypesProto2.NestedEnum
    NEG: TestAllTypesProto2.NestedEnum
    class NestedMessage(Message):
        a: int
        @property
        def corecursive(self) -> TestAllTypesProto2: ...
        def __init__(self, a: Optional[int] = ..., corecursive: Optional[TestAllTypesProto2] = ...) -> None: ...
    class MapInt32Int32Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapInt64Int64Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapUint32Uint32Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapUint64Uint64Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapSint32Sint32Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapSint64Sint64Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapFixed32Fixed32Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapFixed64Fixed64Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapSfixed32Sfixed32Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapSfixed64Sfixed64Entry(Message):
        key: int
        value: int
        def __init__(self, key: Optional[int] = ..., value: Optional[int] = ...) -> None: ...
    class MapInt32FloatEntry(Message):
        key: int
        value: float
        def __init__(self, key: Optional[int] = ..., value: Optional[float] = ...) -> None: ...
    class MapInt32DoubleEntry(Message):
        key: int
        value: float
        def __init__(self, key: Optional[int] = ..., value: Optional[float] = ...) -> None: ...
    class MapBoolBoolEntry(Message):
        key: bool
        value: bool
        def __init__(self, key: Optional[bool] = ..., value: Optional[bool] = ...) -> None: ...
    class MapStringStringEntry(Message):
        key: Text
        value: Text
        def __init__(self, key: Optional[Text] = ..., value: Optional[Text] = ...) -> None: ...
    class MapStringBytesEntry(Message):
        key: Text
        value: bytes
        def __init__(self, key: Optional[Text] = ..., value: Optional[bytes] = ...) -> None: ...
    class MapStringNestedMessageEntry(Message):
        key: Text
        @property
        def value(self) -> TestAllTypesProto2.NestedMessage: ...
        def __init__(self, key: Optional[Text] = ..., value: Optional[TestAllTypesProto2.NestedMessage] = ...) -> None: ...
    class MapStringForeignMessageEntry(Message):
        key: Text
        @property
        def value(self) -> ForeignMessageProto2: ...
        def __init__(self, key: Optional[Text] = ..., value: Optional[ForeignMessageProto2] = ...) -> None: ...
    class MapStringNestedEnumEntry(Message):
        key: Text
        value: TestAllTypesProto2.NestedEnum
        def __init__(self, key: Optional[Text] = ..., value: Optional[TestAllTypesProto2.NestedEnum] = ...) -> None: ...
    class MapStringForeignEnumEntry(Message):
        key: Text
        value: ForeignEnumProto2
        def __init__(self, key: Optional[Text] = ..., value: Optional[ForeignEnumProto2] = ...) -> None: ...
    class Data(Message):
        group_int32: int
        group_uint32: int
        def __init__(self, group_int32: Optional[int] = ..., group_uint32: Optional[int] = ...) -> None: ...
    class MessageSetCorrect(Message):
        def __init__(self,) -> None: ...
    class MessageSetCorrectExtension1(Message):
        bytes: Text
        def __init__(self, bytes: Optional[Text] = ...) -> None: ...
    class MessageSetCorrectExtension2(Message):
        i: int
        def __init__(self, i: Optional[int] = ...) -> None: ...
    optional_int32: int
    optional_int64: int
    optional_uint32: int
    optional_uint64: int
    optional_sint32: int
    optional_sint64: int
    optional_fixed32: int
    optional_fixed64: int
    optional_sfixed32: int
    optional_sfixed64: int
    optional_float: float
    optional_double: float
    optional_bool: bool
    optional_string: Text
    optional_bytes: bytes
    optional_nested_enum: TestAllTypesProto2.NestedEnum
    optional_foreign_enum: ForeignEnumProto2
    optional_string_piece: Text
    optional_cord: Text
    repeated_int32: RepeatedScalarFieldContainer[int]
    repeated_int64: RepeatedScalarFieldContainer[int]
    repeated_uint32: RepeatedScalarFieldContainer[int]
    repeated_uint64: RepeatedScalarFieldContainer[int]
    repeated_sint32: RepeatedScalarFieldContainer[int]
    repeated_sint64: RepeatedScalarFieldContainer[int]
    repeated_fixed32: RepeatedScalarFieldContainer[int]
    repeated_fixed64: RepeatedScalarFieldContainer[int]
    repeated_sfixed32: RepeatedScalarFieldContainer[int]
    repeated_sfixed64: RepeatedScalarFieldContainer[int]
    repeated_float: RepeatedScalarFieldContainer[float]
    repeated_double: RepeatedScalarFieldContainer[float]
    repeated_bool: RepeatedScalarFieldContainer[bool]
    repeated_string: RepeatedScalarFieldContainer[Text]
    repeated_bytes: RepeatedScalarFieldContainer[bytes]
    repeated_nested_enum: RepeatedScalarFieldContainer[TestAllTypesProto2.NestedEnum]
    repeated_foreign_enum: RepeatedScalarFieldContainer[ForeignEnumProto2]
    repeated_string_piece: RepeatedScalarFieldContainer[Text]
    repeated_cord: RepeatedScalarFieldContainer[Text]
    oneof_uint32: int
    oneof_string: Text
    oneof_bytes: bytes
    oneof_bool: bool
    oneof_uint64: int
    oneof_float: float
    oneof_double: float
    oneof_enum: TestAllTypesProto2.NestedEnum
    fieldname1: int
    field_name2: int
    _field_name3: int
    field__name4_: int
    field0name5: int
    field_0_name6: int
    fieldName7: int
    FieldName8: int
    field_Name9: int
    Field_Name10: int
    FIELD_NAME11: int
    FIELD_name12: int
    __field_name13: int
    __Field_name14: int
    field__name15: int
    field__Name16: int
    field_name17__: int
    Field_name18__: int
    @property
    def optional_nested_message(self) -> TestAllTypesProto2.NestedMessage: ...
    @property
    def optional_foreign_message(self) -> ForeignMessageProto2: ...
    @property
    def recursive_message(self) -> TestAllTypesProto2: ...
    @property
    def repeated_nested_message(self) -> RepeatedCompositeFieldContainer[TestAllTypesProto2.NestedMessage]: ...
    @property
    def repeated_foreign_message(self) -> RepeatedCompositeFieldContainer[ForeignMessageProto2]: ...
    @property
    def map_int32_int32(self) -> MutableMapping[int, int]: ...
    @property
    def map_int64_int64(self) -> MutableMapping[int, int]: ...
    @property
    def map_uint32_uint32(self) -> MutableMapping[int, int]: ...
    @property
    def map_uint64_uint64(self) -> MutableMapping[int, int]: ...
    @property
    def map_sint32_sint32(self) -> MutableMapping[int, int]: ...
    @property
    def map_sint64_sint64(self) -> MutableMapping[int, int]: ...
    @property
    def map_fixed32_fixed32(self) -> MutableMapping[int, int]: ...
    @property
    def map_fixed64_fixed64(self) -> MutableMapping[int, int]: ...
    @property
    def map_sfixed32_sfixed32(self) -> MutableMapping[int, int]: ...
    @property
    def map_sfixed64_sfixed64(self) -> MutableMapping[int, int]: ...
    @property
    def map_int32_float(self) -> MutableMapping[int, float]: ...
    @property
    def map_int32_double(self) -> MutableMapping[int, float]: ...
    @property
    def map_bool_bool(self) -> MutableMapping[bool, bool]: ...
    @property
    def map_string_string(self) -> MutableMapping[Text, Text]: ...
    @property
    def map_string_bytes(self) -> MutableMapping[Text, bytes]: ...
    @property
    def map_string_nested_message(self) -> MutableMapping[Text, TestAllTypesProto2.NestedMessage]: ...
    @property
    def map_string_foreign_message(self) -> MutableMapping[Text, ForeignMessageProto2]: ...
    @property
    def map_string_nested_enum(self) -> MutableMapping[Text, TestAllTypesProto2.NestedEnum]: ...
    @property
    def map_string_foreign_enum(self) -> MutableMapping[Text, ForeignEnumProto2]: ...
    @property
    def oneof_nested_message(self) -> TestAllTypesProto2.NestedMessage: ...
    @property
    def data(self) -> TestAllTypesProto2.Data: ...
    def __init__(
        self,
        optional_int32: Optional[int] = ...,
        optional_int64: Optional[int] = ...,
        optional_uint32: Optional[int] = ...,
        optional_uint64: Optional[int] = ...,
        optional_sint32: Optional[int] = ...,
        optional_sint64: Optional[int] = ...,
        optional_fixed32: Optional[int] = ...,
        optional_fixed64: Optional[int] = ...,
        optional_sfixed32: Optional[int] = ...,
        optional_sfixed64: Optional[int] = ...,
        optional_float: Optional[float] = ...,
        optional_double: Optional[float] = ...,
        optional_bool: Optional[bool] = ...,
        optional_string: Optional[Text] = ...,
        optional_bytes: Optional[bytes] = ...,
        optional_nested_message: Optional[TestAllTypesProto2.NestedMessage] = ...,
        optional_foreign_message: Optional[ForeignMessageProto2] = ...,
        optional_nested_enum: Optional[TestAllTypesProto2.NestedEnum] = ...,
        optional_foreign_enum: Optional[ForeignEnumProto2] = ...,
        optional_string_piece: Optional[Text] = ...,
        optional_cord: Optional[Text] = ...,
        recursive_message: Optional[TestAllTypesProto2] = ...,
        repeated_int32: Optional[Iterable[int]] = ...,
        repeated_int64: Optional[Iterable[int]] = ...,
        repeated_uint32: Optional[Iterable[int]] = ...,
        repeated_uint64: Optional[Iterable[int]] = ...,
        repeated_sint32: Optional[Iterable[int]] = ...,
        repeated_sint64: Optional[Iterable[int]] = ...,
        repeated_fixed32: Optional[Iterable[int]] = ...,
        repeated_fixed64: Optional[Iterable[int]] = ...,
        repeated_sfixed32: Optional[Iterable[int]] = ...,
        repeated_sfixed64: Optional[Iterable[int]] = ...,
        repeated_float: Optional[Iterable[float]] = ...,
        repeated_double: Optional[Iterable[float]] = ...,
        repeated_bool: Optional[Iterable[bool]] = ...,
        repeated_string: Optional[Iterable[Text]] = ...,
        repeated_bytes: Optional[Iterable[bytes]] = ...,
        repeated_nested_message: Optional[Iterable[TestAllTypesProto2.NestedMessage]] = ...,
        repeated_foreign_message: Optional[Iterable[ForeignMessageProto2]] = ...,
        repeated_nested_enum: Optional[Iterable[TestAllTypesProto2.NestedEnum]] = ...,
        repeated_foreign_enum: Optional[Iterable[ForeignEnumProto2]] = ...,
        repeated_string_piece: Optional[Iterable[Text]] = ...,
        repeated_cord: Optional[Iterable[Text]] = ...,
        map_int32_int32: Optional[Mapping[int, int]] = ...,
        map_int64_int64: Optional[Mapping[int, int]] = ...,
        map_uint32_uint32: Optional[Mapping[int, int]] = ...,
        map_uint64_uint64: Optional[Mapping[int, int]] = ...,
        map_sint32_sint32: Optional[Mapping[int, int]] = ...,
        map_sint64_sint64: Optional[Mapping[int, int]] = ...,
        map_fixed32_fixed32: Optional[Mapping[int, int]] = ...,
        map_fixed64_fixed64: Optional[Mapping[int, int]] = ...,
        map_sfixed32_sfixed32: Optional[Mapping[int, int]] = ...,
        map_sfixed64_sfixed64: Optional[Mapping[int, int]] = ...,
        map_int32_float: Optional[Mapping[int, float]] = ...,
        map_int32_double: Optional[Mapping[int, float]] = ...,
        map_bool_bool: Optional[Mapping[bool, bool]] = ...,
        map_string_string: Optional[Mapping[Text, Text]] = ...,
        map_string_bytes: Optional[Mapping[Text, bytes]] = ...,
        map_string_nested_message: Optional[Mapping[Text, TestAllTypesProto2.NestedMessage]] = ...,
        map_string_foreign_message: Optional[Mapping[Text, ForeignMessageProto2]] = ...,
        map_string_nested_enum: Optional[Mapping[Text, TestAllTypesProto2.NestedEnum]] = ...,
        map_string_foreign_enum: Optional[Mapping[Text, ForeignEnumProto2]] = ...,
        oneof_uint32: Optional[int] = ...,
        oneof_nested_message: Optional[TestAllTypesProto2.NestedMessage] = ...,
        oneof_string: Optional[Text] = ...,
        oneof_bytes: Optional[bytes] = ...,
        oneof_bool: Optional[bool] = ...,
        oneof_uint64: Optional[int] = ...,
        oneof_float: Optional[float] = ...,
        oneof_double: Optional[float] = ...,
        oneof_enum: Optional[TestAllTypesProto2.NestedEnum] = ...,
        data: Optional[TestAllTypesProto2.Data] = ...,
        fieldname1: Optional[int] = ...,
        field_name2: Optional[int] = ...,
        _field_name3: Optional[int] = ...,
        field__name4_: Optional[int] = ...,
        field0name5: Optional[int] = ...,
        field_0_name6: Optional[int] = ...,
        fieldName7: Optional[int] = ...,
        FieldName8: Optional[int] = ...,
        field_Name9: Optional[int] = ...,
        Field_Name10: Optional[int] = ...,
        FIELD_NAME11: Optional[int] = ...,
        FIELD_name12: Optional[int] = ...,
        __field_name13: Optional[int] = ...,
        __Field_name14: Optional[int] = ...,
        field__name15: Optional[int] = ...,
        field__Name16: Optional[int] = ...,
        field_name17__: Optional[int] = ...,
        Field_name18__: Optional[int] = ...,
    ) -> None: ...

class ForeignMessageProto2(Message):
    c: int
    def __init__(self, c: Optional[int] = ...) -> None: ...
