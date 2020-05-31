from google.protobuf.internal.containers import RepeatedCompositeFieldContainer, RepeatedScalarFieldContainer
from google.protobuf.message import Message
from google.protobuf.unittest_import_pb2 import ImportMessage
from google.protobuf.unittest_import_public_pb2 import PublicImportMessage
from typing import Iterable, List, Optional, Text, Tuple, cast

class ForeignEnum(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> ForeignEnum: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[ForeignEnum]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, ForeignEnum]]: ...

FOREIGN_ZERO: ForeignEnum
FOREIGN_FOO: ForeignEnum
FOREIGN_BAR: ForeignEnum
FOREIGN_BAZ: ForeignEnum

class TestAllTypes(Message):
    class NestedEnum(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> TestAllTypes.NestedEnum: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[TestAllTypes.NestedEnum]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, TestAllTypes.NestedEnum]]: ...
    ZERO: TestAllTypes.NestedEnum
    FOO: TestAllTypes.NestedEnum
    BAR: TestAllTypes.NestedEnum
    BAZ: TestAllTypes.NestedEnum
    NEG: TestAllTypes.NestedEnum
    class NestedMessage(Message):
        bb: int
        def __init__(self, bb: Optional[int] = ...) -> None: ...
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
    optional_nested_enum: TestAllTypes.NestedEnum
    optional_foreign_enum: ForeignEnum
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
    repeated_nested_enum: RepeatedScalarFieldContainer[TestAllTypes.NestedEnum]
    repeated_foreign_enum: RepeatedScalarFieldContainer[ForeignEnum]
    repeated_string_piece: RepeatedScalarFieldContainer[Text]
    repeated_cord: RepeatedScalarFieldContainer[Text]
    oneof_uint32: int
    oneof_string: Text
    oneof_bytes: bytes
    @property
    def optional_nested_message(self) -> TestAllTypes.NestedMessage: ...
    @property
    def optional_foreign_message(self) -> ForeignMessage: ...
    @property
    def optional_import_message(self) -> ImportMessage: ...
    @property
    def optional_public_import_message(self) -> PublicImportMessage: ...
    @property
    def optional_lazy_message(self) -> TestAllTypes.NestedMessage: ...
    @property
    def optional_lazy_import_message(self) -> ImportMessage: ...
    @property
    def repeated_nested_message(self) -> RepeatedCompositeFieldContainer[TestAllTypes.NestedMessage]: ...
    @property
    def repeated_foreign_message(self) -> RepeatedCompositeFieldContainer[ForeignMessage]: ...
    @property
    def repeated_import_message(self) -> RepeatedCompositeFieldContainer[ImportMessage]: ...
    @property
    def repeated_lazy_message(self) -> RepeatedCompositeFieldContainer[TestAllTypes.NestedMessage]: ...
    @property
    def oneof_nested_message(self) -> TestAllTypes.NestedMessage: ...
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
        optional_nested_message: Optional[TestAllTypes.NestedMessage] = ...,
        optional_foreign_message: Optional[ForeignMessage] = ...,
        optional_import_message: Optional[ImportMessage] = ...,
        optional_nested_enum: Optional[TestAllTypes.NestedEnum] = ...,
        optional_foreign_enum: Optional[ForeignEnum] = ...,
        optional_string_piece: Optional[Text] = ...,
        optional_cord: Optional[Text] = ...,
        optional_public_import_message: Optional[PublicImportMessage] = ...,
        optional_lazy_message: Optional[TestAllTypes.NestedMessage] = ...,
        optional_lazy_import_message: Optional[ImportMessage] = ...,
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
        repeated_nested_message: Optional[Iterable[TestAllTypes.NestedMessage]] = ...,
        repeated_foreign_message: Optional[Iterable[ForeignMessage]] = ...,
        repeated_import_message: Optional[Iterable[ImportMessage]] = ...,
        repeated_nested_enum: Optional[Iterable[TestAllTypes.NestedEnum]] = ...,
        repeated_foreign_enum: Optional[Iterable[ForeignEnum]] = ...,
        repeated_string_piece: Optional[Iterable[Text]] = ...,
        repeated_cord: Optional[Iterable[Text]] = ...,
        repeated_lazy_message: Optional[Iterable[TestAllTypes.NestedMessage]] = ...,
        oneof_uint32: Optional[int] = ...,
        oneof_nested_message: Optional[TestAllTypes.NestedMessage] = ...,
        oneof_string: Optional[Text] = ...,
        oneof_bytes: Optional[bytes] = ...,
    ) -> None: ...

class TestPackedTypes(Message):
    packed_int32: RepeatedScalarFieldContainer[int]
    packed_int64: RepeatedScalarFieldContainer[int]
    packed_uint32: RepeatedScalarFieldContainer[int]
    packed_uint64: RepeatedScalarFieldContainer[int]
    packed_sint32: RepeatedScalarFieldContainer[int]
    packed_sint64: RepeatedScalarFieldContainer[int]
    packed_fixed32: RepeatedScalarFieldContainer[int]
    packed_fixed64: RepeatedScalarFieldContainer[int]
    packed_sfixed32: RepeatedScalarFieldContainer[int]
    packed_sfixed64: RepeatedScalarFieldContainer[int]
    packed_float: RepeatedScalarFieldContainer[float]
    packed_double: RepeatedScalarFieldContainer[float]
    packed_bool: RepeatedScalarFieldContainer[bool]
    packed_enum: RepeatedScalarFieldContainer[ForeignEnum]
    def __init__(
        self,
        packed_int32: Optional[Iterable[int]] = ...,
        packed_int64: Optional[Iterable[int]] = ...,
        packed_uint32: Optional[Iterable[int]] = ...,
        packed_uint64: Optional[Iterable[int]] = ...,
        packed_sint32: Optional[Iterable[int]] = ...,
        packed_sint64: Optional[Iterable[int]] = ...,
        packed_fixed32: Optional[Iterable[int]] = ...,
        packed_fixed64: Optional[Iterable[int]] = ...,
        packed_sfixed32: Optional[Iterable[int]] = ...,
        packed_sfixed64: Optional[Iterable[int]] = ...,
        packed_float: Optional[Iterable[float]] = ...,
        packed_double: Optional[Iterable[float]] = ...,
        packed_bool: Optional[Iterable[bool]] = ...,
        packed_enum: Optional[Iterable[ForeignEnum]] = ...,
    ) -> None: ...

class TestUnpackedTypes(Message):
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
    repeated_nested_enum: RepeatedScalarFieldContainer[TestAllTypes.NestedEnum]
    def __init__(
        self,
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
        repeated_nested_enum: Optional[Iterable[TestAllTypes.NestedEnum]] = ...,
    ) -> None: ...

class NestedTestAllTypes(Message):
    @property
    def child(self) -> NestedTestAllTypes: ...
    @property
    def payload(self) -> TestAllTypes: ...
    @property
    def repeated_child(self) -> RepeatedCompositeFieldContainer[NestedTestAllTypes]: ...
    def __init__(
        self,
        child: Optional[NestedTestAllTypes] = ...,
        payload: Optional[TestAllTypes] = ...,
        repeated_child: Optional[Iterable[NestedTestAllTypes]] = ...,
    ) -> None: ...

class ForeignMessage(Message):
    c: int
    def __init__(self, c: Optional[int] = ...) -> None: ...

class TestEmptyMessage(Message):
    def __init__(self,) -> None: ...
