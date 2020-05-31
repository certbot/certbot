from google.protobuf.internal.containers import RepeatedCompositeFieldContainer, RepeatedScalarFieldContainer
from google.protobuf.message import Message
from google.protobuf.unittest_import_pb2 import ImportEnum, ImportMessage
from google.protobuf.unittest_import_public_pb2 import PublicImportMessage
from typing import Iterable, List, Mapping, MutableMapping, Optional, Text, Tuple, cast

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

FOREIGN_FOO: ForeignEnum
FOREIGN_BAR: ForeignEnum
FOREIGN_BAZ: ForeignEnum

class TestEnumWithDupValue(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> TestEnumWithDupValue: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[TestEnumWithDupValue]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, TestEnumWithDupValue]]: ...

FOO1: TestEnumWithDupValue
BAR1: TestEnumWithDupValue
BAZ: TestEnumWithDupValue
FOO2: TestEnumWithDupValue
BAR2: TestEnumWithDupValue

class TestSparseEnum(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> TestSparseEnum: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[TestSparseEnum]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, TestSparseEnum]]: ...

SPARSE_A: TestSparseEnum
SPARSE_B: TestSparseEnum
SPARSE_C: TestSparseEnum
SPARSE_D: TestSparseEnum
SPARSE_E: TestSparseEnum
SPARSE_F: TestSparseEnum
SPARSE_G: TestSparseEnum

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
    FOO: TestAllTypes.NestedEnum
    BAR: TestAllTypes.NestedEnum
    BAZ: TestAllTypes.NestedEnum
    NEG: TestAllTypes.NestedEnum
    class NestedMessage(Message):
        bb: int
        def __init__(self, bb: Optional[int] = ...) -> None: ...
    class OptionalGroup(Message):
        a: int
        def __init__(self, a: Optional[int] = ...) -> None: ...
    class RepeatedGroup(Message):
        a: int
        def __init__(self, a: Optional[int] = ...) -> None: ...
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
    optional_import_enum: ImportEnum
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
    repeated_import_enum: RepeatedScalarFieldContainer[ImportEnum]
    repeated_string_piece: RepeatedScalarFieldContainer[Text]
    repeated_cord: RepeatedScalarFieldContainer[Text]
    default_int32: int
    default_int64: int
    default_uint32: int
    default_uint64: int
    default_sint32: int
    default_sint64: int
    default_fixed32: int
    default_fixed64: int
    default_sfixed32: int
    default_sfixed64: int
    default_float: float
    default_double: float
    default_bool: bool
    default_string: Text
    default_bytes: bytes
    default_nested_enum: TestAllTypes.NestedEnum
    default_foreign_enum: ForeignEnum
    default_import_enum: ImportEnum
    default_string_piece: Text
    default_cord: Text
    oneof_uint32: int
    oneof_string: Text
    oneof_bytes: bytes
    @property
    def optionalgroup(self) -> TestAllTypes.OptionalGroup: ...
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
    def repeatedgroup(self) -> RepeatedCompositeFieldContainer[TestAllTypes.RepeatedGroup]: ...
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
        optionalgroup: Optional[TestAllTypes.OptionalGroup] = ...,
        optional_nested_message: Optional[TestAllTypes.NestedMessage] = ...,
        optional_foreign_message: Optional[ForeignMessage] = ...,
        optional_import_message: Optional[ImportMessage] = ...,
        optional_nested_enum: Optional[TestAllTypes.NestedEnum] = ...,
        optional_foreign_enum: Optional[ForeignEnum] = ...,
        optional_import_enum: Optional[ImportEnum] = ...,
        optional_string_piece: Optional[Text] = ...,
        optional_cord: Optional[Text] = ...,
        optional_public_import_message: Optional[PublicImportMessage] = ...,
        optional_lazy_message: Optional[TestAllTypes.NestedMessage] = ...,
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
        repeatedgroup: Optional[Iterable[TestAllTypes.RepeatedGroup]] = ...,
        repeated_nested_message: Optional[Iterable[TestAllTypes.NestedMessage]] = ...,
        repeated_foreign_message: Optional[Iterable[ForeignMessage]] = ...,
        repeated_import_message: Optional[Iterable[ImportMessage]] = ...,
        repeated_nested_enum: Optional[Iterable[TestAllTypes.NestedEnum]] = ...,
        repeated_foreign_enum: Optional[Iterable[ForeignEnum]] = ...,
        repeated_import_enum: Optional[Iterable[ImportEnum]] = ...,
        repeated_string_piece: Optional[Iterable[Text]] = ...,
        repeated_cord: Optional[Iterable[Text]] = ...,
        repeated_lazy_message: Optional[Iterable[TestAllTypes.NestedMessage]] = ...,
        default_int32: Optional[int] = ...,
        default_int64: Optional[int] = ...,
        default_uint32: Optional[int] = ...,
        default_uint64: Optional[int] = ...,
        default_sint32: Optional[int] = ...,
        default_sint64: Optional[int] = ...,
        default_fixed32: Optional[int] = ...,
        default_fixed64: Optional[int] = ...,
        default_sfixed32: Optional[int] = ...,
        default_sfixed64: Optional[int] = ...,
        default_float: Optional[float] = ...,
        default_double: Optional[float] = ...,
        default_bool: Optional[bool] = ...,
        default_string: Optional[Text] = ...,
        default_bytes: Optional[bytes] = ...,
        default_nested_enum: Optional[TestAllTypes.NestedEnum] = ...,
        default_foreign_enum: Optional[ForeignEnum] = ...,
        default_import_enum: Optional[ImportEnum] = ...,
        default_string_piece: Optional[Text] = ...,
        default_cord: Optional[Text] = ...,
        oneof_uint32: Optional[int] = ...,
        oneof_nested_message: Optional[TestAllTypes.NestedMessage] = ...,
        oneof_string: Optional[Text] = ...,
        oneof_bytes: Optional[bytes] = ...,
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

class TestDeprecatedFields(Message):
    deprecated_int32: int
    deprecated_int32_in_oneof: int
    def __init__(self, deprecated_int32: Optional[int] = ..., deprecated_int32_in_oneof: Optional[int] = ...) -> None: ...

class TestDeprecatedMessage(Message):
    def __init__(self,) -> None: ...

class ForeignMessage(Message):
    c: int
    d: int
    def __init__(self, c: Optional[int] = ..., d: Optional[int] = ...) -> None: ...

class TestReservedFields(Message):
    def __init__(self,) -> None: ...

class TestAllExtensions(Message):
    def __init__(self,) -> None: ...

class OptionalGroup_extension(Message):
    a: int
    def __init__(self, a: Optional[int] = ...) -> None: ...

class RepeatedGroup_extension(Message):
    a: int
    def __init__(self, a: Optional[int] = ...) -> None: ...

class TestGroup(Message):
    class OptionalGroup(Message):
        a: int
        def __init__(self, a: Optional[int] = ...) -> None: ...
    optional_foreign_enum: ForeignEnum
    @property
    def optionalgroup(self) -> TestGroup.OptionalGroup: ...
    def __init__(
        self, optionalgroup: Optional[TestGroup.OptionalGroup] = ..., optional_foreign_enum: Optional[ForeignEnum] = ...
    ) -> None: ...

class TestGroupExtension(Message):
    def __init__(self,) -> None: ...

class TestNestedExtension(Message):
    class OptionalGroup_extension(Message):
        a: int
        def __init__(self, a: Optional[int] = ...) -> None: ...
    def __init__(self,) -> None: ...

class TestRequired(Message):
    a: int
    dummy2: int
    b: int
    dummy4: int
    dummy5: int
    dummy6: int
    dummy7: int
    dummy8: int
    dummy9: int
    dummy10: int
    dummy11: int
    dummy12: int
    dummy13: int
    dummy14: int
    dummy15: int
    dummy16: int
    dummy17: int
    dummy18: int
    dummy19: int
    dummy20: int
    dummy21: int
    dummy22: int
    dummy23: int
    dummy24: int
    dummy25: int
    dummy26: int
    dummy27: int
    dummy28: int
    dummy29: int
    dummy30: int
    dummy31: int
    dummy32: int
    c: int
    def __init__(
        self,
        a: int,
        b: int,
        c: int,
        dummy2: Optional[int] = ...,
        dummy4: Optional[int] = ...,
        dummy5: Optional[int] = ...,
        dummy6: Optional[int] = ...,
        dummy7: Optional[int] = ...,
        dummy8: Optional[int] = ...,
        dummy9: Optional[int] = ...,
        dummy10: Optional[int] = ...,
        dummy11: Optional[int] = ...,
        dummy12: Optional[int] = ...,
        dummy13: Optional[int] = ...,
        dummy14: Optional[int] = ...,
        dummy15: Optional[int] = ...,
        dummy16: Optional[int] = ...,
        dummy17: Optional[int] = ...,
        dummy18: Optional[int] = ...,
        dummy19: Optional[int] = ...,
        dummy20: Optional[int] = ...,
        dummy21: Optional[int] = ...,
        dummy22: Optional[int] = ...,
        dummy23: Optional[int] = ...,
        dummy24: Optional[int] = ...,
        dummy25: Optional[int] = ...,
        dummy26: Optional[int] = ...,
        dummy27: Optional[int] = ...,
        dummy28: Optional[int] = ...,
        dummy29: Optional[int] = ...,
        dummy30: Optional[int] = ...,
        dummy31: Optional[int] = ...,
        dummy32: Optional[int] = ...,
    ) -> None: ...

class TestRequiredForeign(Message):
    dummy: int
    @property
    def optional_message(self) -> TestRequired: ...
    @property
    def repeated_message(self) -> RepeatedCompositeFieldContainer[TestRequired]: ...
    def __init__(
        self,
        optional_message: Optional[TestRequired] = ...,
        repeated_message: Optional[Iterable[TestRequired]] = ...,
        dummy: Optional[int] = ...,
    ) -> None: ...

class TestRequiredMessage(Message):
    @property
    def optional_message(self) -> TestRequired: ...
    @property
    def repeated_message(self) -> RepeatedCompositeFieldContainer[TestRequired]: ...
    @property
    def required_message(self) -> TestRequired: ...
    def __init__(
        self,
        required_message: TestRequired,
        optional_message: Optional[TestRequired] = ...,
        repeated_message: Optional[Iterable[TestRequired]] = ...,
    ) -> None: ...

class TestForeignNested(Message):
    @property
    def foreign_nested(self) -> TestAllTypes.NestedMessage: ...
    def __init__(self, foreign_nested: Optional[TestAllTypes.NestedMessage] = ...) -> None: ...

class TestEmptyMessage(Message):
    def __init__(self,) -> None: ...

class TestEmptyMessageWithExtensions(Message):
    def __init__(self,) -> None: ...

class TestMultipleExtensionRanges(Message):
    def __init__(self,) -> None: ...

class TestReallyLargeTagNumber(Message):
    a: int
    bb: int
    def __init__(self, a: Optional[int] = ..., bb: Optional[int] = ...) -> None: ...

class TestRecursiveMessage(Message):
    i: int
    @property
    def a(self) -> TestRecursiveMessage: ...
    def __init__(self, a: Optional[TestRecursiveMessage] = ..., i: Optional[int] = ...) -> None: ...

class TestMutualRecursionA(Message):
    class SubMessage(Message):
        @property
        def b(self) -> TestMutualRecursionB: ...
        def __init__(self, b: Optional[TestMutualRecursionB] = ...) -> None: ...
    class SubGroup(Message):
        @property
        def sub_message(self) -> TestMutualRecursionA.SubMessage: ...
        @property
        def not_in_this_scc(self) -> TestAllTypes: ...
        def __init__(
            self, sub_message: Optional[TestMutualRecursionA.SubMessage] = ..., not_in_this_scc: Optional[TestAllTypes] = ...
        ) -> None: ...
    @property
    def bb(self) -> TestMutualRecursionB: ...
    @property
    def subgroup(self) -> TestMutualRecursionA.SubGroup: ...
    def __init__(
        self, bb: Optional[TestMutualRecursionB] = ..., subgroup: Optional[TestMutualRecursionA.SubGroup] = ...
    ) -> None: ...

class TestMutualRecursionB(Message):
    optional_int32: int
    @property
    def a(self) -> TestMutualRecursionA: ...
    def __init__(self, a: Optional[TestMutualRecursionA] = ..., optional_int32: Optional[int] = ...) -> None: ...

class TestIsInitialized(Message):
    class SubMessage(Message):
        class SubGroup(Message):
            i: int
            def __init__(self, i: int) -> None: ...
        @property
        def subgroup(self) -> TestIsInitialized.SubMessage.SubGroup: ...
        def __init__(self, subgroup: Optional[TestIsInitialized.SubMessage.SubGroup] = ...) -> None: ...
    @property
    def sub_message(self) -> TestIsInitialized.SubMessage: ...
    def __init__(self, sub_message: Optional[TestIsInitialized.SubMessage] = ...) -> None: ...

class TestDupFieldNumber(Message):
    class Foo(Message):
        a: int
        def __init__(self, a: Optional[int] = ...) -> None: ...
    class Bar(Message):
        a: int
        def __init__(self, a: Optional[int] = ...) -> None: ...
    a: int
    @property
    def foo(self) -> TestDupFieldNumber.Foo: ...
    @property
    def bar(self) -> TestDupFieldNumber.Bar: ...
    def __init__(
        self, a: Optional[int] = ..., foo: Optional[TestDupFieldNumber.Foo] = ..., bar: Optional[TestDupFieldNumber.Bar] = ...
    ) -> None: ...

class TestEagerMessage(Message):
    @property
    def sub_message(self) -> TestAllTypes: ...
    def __init__(self, sub_message: Optional[TestAllTypes] = ...) -> None: ...

class TestLazyMessage(Message):
    @property
    def sub_message(self) -> TestAllTypes: ...
    def __init__(self, sub_message: Optional[TestAllTypes] = ...) -> None: ...

class TestNestedMessageHasBits(Message):
    class NestedMessage(Message):
        nestedmessage_repeated_int32: RepeatedScalarFieldContainer[int]
        @property
        def nestedmessage_repeated_foreignmessage(self) -> RepeatedCompositeFieldContainer[ForeignMessage]: ...
        def __init__(
            self,
            nestedmessage_repeated_int32: Optional[Iterable[int]] = ...,
            nestedmessage_repeated_foreignmessage: Optional[Iterable[ForeignMessage]] = ...,
        ) -> None: ...
    @property
    def optional_nested_message(self) -> TestNestedMessageHasBits.NestedMessage: ...
    def __init__(self, optional_nested_message: Optional[TestNestedMessageHasBits.NestedMessage] = ...) -> None: ...

class TestCamelCaseFieldNames(Message):
    PrimitiveField: int
    StringField: Text
    EnumField: ForeignEnum
    StringPieceField: Text
    CordField: Text
    RepeatedPrimitiveField: RepeatedScalarFieldContainer[int]
    RepeatedStringField: RepeatedScalarFieldContainer[Text]
    RepeatedEnumField: RepeatedScalarFieldContainer[ForeignEnum]
    RepeatedStringPieceField: RepeatedScalarFieldContainer[Text]
    RepeatedCordField: RepeatedScalarFieldContainer[Text]
    @property
    def MessageField(self) -> ForeignMessage: ...
    @property
    def RepeatedMessageField(self) -> RepeatedCompositeFieldContainer[ForeignMessage]: ...
    def __init__(
        self,
        PrimitiveField: Optional[int] = ...,
        StringField: Optional[Text] = ...,
        EnumField: Optional[ForeignEnum] = ...,
        MessageField: Optional[ForeignMessage] = ...,
        StringPieceField: Optional[Text] = ...,
        CordField: Optional[Text] = ...,
        RepeatedPrimitiveField: Optional[Iterable[int]] = ...,
        RepeatedStringField: Optional[Iterable[Text]] = ...,
        RepeatedEnumField: Optional[Iterable[ForeignEnum]] = ...,
        RepeatedMessageField: Optional[Iterable[ForeignMessage]] = ...,
        RepeatedStringPieceField: Optional[Iterable[Text]] = ...,
        RepeatedCordField: Optional[Iterable[Text]] = ...,
    ) -> None: ...

class TestFieldOrderings(Message):
    class NestedMessage(Message):
        oo: int
        bb: int
        def __init__(self, oo: Optional[int] = ..., bb: Optional[int] = ...) -> None: ...
    my_string: Text
    my_int: int
    my_float: float
    @property
    def optional_nested_message(self) -> TestFieldOrderings.NestedMessage: ...
    def __init__(
        self,
        my_string: Optional[Text] = ...,
        my_int: Optional[int] = ...,
        my_float: Optional[float] = ...,
        optional_nested_message: Optional[TestFieldOrderings.NestedMessage] = ...,
    ) -> None: ...

class TestExtensionOrderings1(Message):
    my_string: Text
    def __init__(self, my_string: Optional[Text] = ...) -> None: ...

class TestExtensionOrderings2(Message):
    class TestExtensionOrderings3(Message):
        my_string: Text
        def __init__(self, my_string: Optional[Text] = ...) -> None: ...
    my_string: Text
    def __init__(self, my_string: Optional[Text] = ...) -> None: ...

class TestExtremeDefaultValues(Message):
    escaped_bytes: bytes
    large_uint32: int
    large_uint64: int
    small_int32: int
    small_int64: int
    really_small_int32: int
    really_small_int64: int
    utf8_string: Text
    zero_float: float
    one_float: float
    small_float: float
    negative_one_float: float
    negative_float: float
    large_float: float
    small_negative_float: float
    inf_double: float
    neg_inf_double: float
    nan_double: float
    inf_float: float
    neg_inf_float: float
    nan_float: float
    cpp_trigraph: Text
    string_with_zero: Text
    bytes_with_zero: bytes
    string_piece_with_zero: Text
    cord_with_zero: Text
    replacement_string: Text
    def __init__(
        self,
        escaped_bytes: Optional[bytes] = ...,
        large_uint32: Optional[int] = ...,
        large_uint64: Optional[int] = ...,
        small_int32: Optional[int] = ...,
        small_int64: Optional[int] = ...,
        really_small_int32: Optional[int] = ...,
        really_small_int64: Optional[int] = ...,
        utf8_string: Optional[Text] = ...,
        zero_float: Optional[float] = ...,
        one_float: Optional[float] = ...,
        small_float: Optional[float] = ...,
        negative_one_float: Optional[float] = ...,
        negative_float: Optional[float] = ...,
        large_float: Optional[float] = ...,
        small_negative_float: Optional[float] = ...,
        inf_double: Optional[float] = ...,
        neg_inf_double: Optional[float] = ...,
        nan_double: Optional[float] = ...,
        inf_float: Optional[float] = ...,
        neg_inf_float: Optional[float] = ...,
        nan_float: Optional[float] = ...,
        cpp_trigraph: Optional[Text] = ...,
        string_with_zero: Optional[Text] = ...,
        bytes_with_zero: Optional[bytes] = ...,
        string_piece_with_zero: Optional[Text] = ...,
        cord_with_zero: Optional[Text] = ...,
        replacement_string: Optional[Text] = ...,
    ) -> None: ...

class SparseEnumMessage(Message):
    sparse_enum: TestSparseEnum
    def __init__(self, sparse_enum: Optional[TestSparseEnum] = ...) -> None: ...

class OneString(Message):
    data: Text
    def __init__(self, data: Optional[Text] = ...) -> None: ...

class MoreString(Message):
    data: RepeatedScalarFieldContainer[Text]
    def __init__(self, data: Optional[Iterable[Text]] = ...) -> None: ...

class OneBytes(Message):
    data: bytes
    def __init__(self, data: Optional[bytes] = ...) -> None: ...

class MoreBytes(Message):
    data: RepeatedScalarFieldContainer[bytes]
    def __init__(self, data: Optional[Iterable[bytes]] = ...) -> None: ...

class Int32Message(Message):
    data: int
    def __init__(self, data: Optional[int] = ...) -> None: ...

class Uint32Message(Message):
    data: int
    def __init__(self, data: Optional[int] = ...) -> None: ...

class Int64Message(Message):
    data: int
    def __init__(self, data: Optional[int] = ...) -> None: ...

class Uint64Message(Message):
    data: int
    def __init__(self, data: Optional[int] = ...) -> None: ...

class BoolMessage(Message):
    data: bool
    def __init__(self, data: Optional[bool] = ...) -> None: ...

class TestOneof(Message):
    class FooGroup(Message):
        a: int
        b: Text
        def __init__(self, a: Optional[int] = ..., b: Optional[Text] = ...) -> None: ...
    foo_int: int
    foo_string: Text
    @property
    def foo_message(self) -> TestAllTypes: ...
    @property
    def foogroup(self) -> TestOneof.FooGroup: ...
    def __init__(
        self,
        foo_int: Optional[int] = ...,
        foo_string: Optional[Text] = ...,
        foo_message: Optional[TestAllTypes] = ...,
        foogroup: Optional[TestOneof.FooGroup] = ...,
    ) -> None: ...

class TestOneofBackwardsCompatible(Message):
    class FooGroup(Message):
        a: int
        b: Text
        def __init__(self, a: Optional[int] = ..., b: Optional[Text] = ...) -> None: ...
    foo_int: int
    foo_string: Text
    @property
    def foo_message(self) -> TestAllTypes: ...
    @property
    def foogroup(self) -> TestOneofBackwardsCompatible.FooGroup: ...
    def __init__(
        self,
        foo_int: Optional[int] = ...,
        foo_string: Optional[Text] = ...,
        foo_message: Optional[TestAllTypes] = ...,
        foogroup: Optional[TestOneofBackwardsCompatible.FooGroup] = ...,
    ) -> None: ...

class TestOneof2(Message):
    class NestedEnum(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> TestOneof2.NestedEnum: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[TestOneof2.NestedEnum]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, TestOneof2.NestedEnum]]: ...
    FOO: TestOneof2.NestedEnum
    BAR: TestOneof2.NestedEnum
    BAZ: TestOneof2.NestedEnum
    class FooGroup(Message):
        a: int
        b: Text
        def __init__(self, a: Optional[int] = ..., b: Optional[Text] = ...) -> None: ...
    class NestedMessage(Message):
        qux_int: int
        corge_int: RepeatedScalarFieldContainer[int]
        def __init__(self, qux_int: Optional[int] = ..., corge_int: Optional[Iterable[int]] = ...) -> None: ...
    foo_int: int
    foo_string: Text
    foo_cord: Text
    foo_string_piece: Text
    foo_bytes: bytes
    foo_enum: TestOneof2.NestedEnum
    bar_int: int
    bar_string: Text
    bar_cord: Text
    bar_string_piece: Text
    bar_bytes: bytes
    bar_enum: TestOneof2.NestedEnum
    baz_int: int
    baz_string: Text
    @property
    def foo_message(self) -> TestOneof2.NestedMessage: ...
    @property
    def foogroup(self) -> TestOneof2.FooGroup: ...
    @property
    def foo_lazy_message(self) -> TestOneof2.NestedMessage: ...
    def __init__(
        self,
        foo_int: Optional[int] = ...,
        foo_string: Optional[Text] = ...,
        foo_cord: Optional[Text] = ...,
        foo_string_piece: Optional[Text] = ...,
        foo_bytes: Optional[bytes] = ...,
        foo_enum: Optional[TestOneof2.NestedEnum] = ...,
        foo_message: Optional[TestOneof2.NestedMessage] = ...,
        foogroup: Optional[TestOneof2.FooGroup] = ...,
        foo_lazy_message: Optional[TestOneof2.NestedMessage] = ...,
        bar_int: Optional[int] = ...,
        bar_string: Optional[Text] = ...,
        bar_cord: Optional[Text] = ...,
        bar_string_piece: Optional[Text] = ...,
        bar_bytes: Optional[bytes] = ...,
        bar_enum: Optional[TestOneof2.NestedEnum] = ...,
        baz_int: Optional[int] = ...,
        baz_string: Optional[Text] = ...,
    ) -> None: ...

class TestRequiredOneof(Message):
    class NestedMessage(Message):
        required_double: float
        def __init__(self, required_double: float) -> None: ...
    foo_int: int
    foo_string: Text
    @property
    def foo_message(self) -> TestRequiredOneof.NestedMessage: ...
    def __init__(
        self,
        foo_int: Optional[int] = ...,
        foo_string: Optional[Text] = ...,
        foo_message: Optional[TestRequiredOneof.NestedMessage] = ...,
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
    unpacked_int32: RepeatedScalarFieldContainer[int]
    unpacked_int64: RepeatedScalarFieldContainer[int]
    unpacked_uint32: RepeatedScalarFieldContainer[int]
    unpacked_uint64: RepeatedScalarFieldContainer[int]
    unpacked_sint32: RepeatedScalarFieldContainer[int]
    unpacked_sint64: RepeatedScalarFieldContainer[int]
    unpacked_fixed32: RepeatedScalarFieldContainer[int]
    unpacked_fixed64: RepeatedScalarFieldContainer[int]
    unpacked_sfixed32: RepeatedScalarFieldContainer[int]
    unpacked_sfixed64: RepeatedScalarFieldContainer[int]
    unpacked_float: RepeatedScalarFieldContainer[float]
    unpacked_double: RepeatedScalarFieldContainer[float]
    unpacked_bool: RepeatedScalarFieldContainer[bool]
    unpacked_enum: RepeatedScalarFieldContainer[ForeignEnum]
    def __init__(
        self,
        unpacked_int32: Optional[Iterable[int]] = ...,
        unpacked_int64: Optional[Iterable[int]] = ...,
        unpacked_uint32: Optional[Iterable[int]] = ...,
        unpacked_uint64: Optional[Iterable[int]] = ...,
        unpacked_sint32: Optional[Iterable[int]] = ...,
        unpacked_sint64: Optional[Iterable[int]] = ...,
        unpacked_fixed32: Optional[Iterable[int]] = ...,
        unpacked_fixed64: Optional[Iterable[int]] = ...,
        unpacked_sfixed32: Optional[Iterable[int]] = ...,
        unpacked_sfixed64: Optional[Iterable[int]] = ...,
        unpacked_float: Optional[Iterable[float]] = ...,
        unpacked_double: Optional[Iterable[float]] = ...,
        unpacked_bool: Optional[Iterable[bool]] = ...,
        unpacked_enum: Optional[Iterable[ForeignEnum]] = ...,
    ) -> None: ...

class TestPackedExtensions(Message):
    def __init__(self,) -> None: ...

class TestUnpackedExtensions(Message):
    def __init__(self,) -> None: ...

class TestDynamicExtensions(Message):
    class DynamicEnumType(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> TestDynamicExtensions.DynamicEnumType: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[TestDynamicExtensions.DynamicEnumType]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, TestDynamicExtensions.DynamicEnumType]]: ...
    DYNAMIC_FOO: TestDynamicExtensions.DynamicEnumType
    DYNAMIC_BAR: TestDynamicExtensions.DynamicEnumType
    DYNAMIC_BAZ: TestDynamicExtensions.DynamicEnumType
    class DynamicMessageType(Message):
        dynamic_field: int
        def __init__(self, dynamic_field: Optional[int] = ...) -> None: ...
    scalar_extension: int
    enum_extension: ForeignEnum
    dynamic_enum_extension: TestDynamicExtensions.DynamicEnumType
    repeated_extension: RepeatedScalarFieldContainer[Text]
    packed_extension: RepeatedScalarFieldContainer[int]
    @property
    def message_extension(self) -> ForeignMessage: ...
    @property
    def dynamic_message_extension(self) -> TestDynamicExtensions.DynamicMessageType: ...
    def __init__(
        self,
        scalar_extension: Optional[int] = ...,
        enum_extension: Optional[ForeignEnum] = ...,
        dynamic_enum_extension: Optional[TestDynamicExtensions.DynamicEnumType] = ...,
        message_extension: Optional[ForeignMessage] = ...,
        dynamic_message_extension: Optional[TestDynamicExtensions.DynamicMessageType] = ...,
        repeated_extension: Optional[Iterable[Text]] = ...,
        packed_extension: Optional[Iterable[int]] = ...,
    ) -> None: ...

class TestRepeatedScalarDifferentTagSizes(Message):
    repeated_fixed32: RepeatedScalarFieldContainer[int]
    repeated_int32: RepeatedScalarFieldContainer[int]
    repeated_fixed64: RepeatedScalarFieldContainer[int]
    repeated_int64: RepeatedScalarFieldContainer[int]
    repeated_float: RepeatedScalarFieldContainer[float]
    repeated_uint64: RepeatedScalarFieldContainer[int]
    def __init__(
        self,
        repeated_fixed32: Optional[Iterable[int]] = ...,
        repeated_int32: Optional[Iterable[int]] = ...,
        repeated_fixed64: Optional[Iterable[int]] = ...,
        repeated_int64: Optional[Iterable[int]] = ...,
        repeated_float: Optional[Iterable[float]] = ...,
        repeated_uint64: Optional[Iterable[int]] = ...,
    ) -> None: ...

class TestParsingMerge(Message):
    class RepeatedFieldsGenerator(Message):
        class Group1(Message):
            @property
            def field1(self) -> TestAllTypes: ...
            def __init__(self, field1: Optional[TestAllTypes] = ...) -> None: ...
        class Group2(Message):
            @property
            def field1(self) -> TestAllTypes: ...
            def __init__(self, field1: Optional[TestAllTypes] = ...) -> None: ...
        @property
        def field1(self) -> RepeatedCompositeFieldContainer[TestAllTypes]: ...
        @property
        def field2(self) -> RepeatedCompositeFieldContainer[TestAllTypes]: ...
        @property
        def field3(self) -> RepeatedCompositeFieldContainer[TestAllTypes]: ...
        @property
        def group1(self) -> RepeatedCompositeFieldContainer[TestParsingMerge.RepeatedFieldsGenerator.Group1]: ...
        @property
        def group2(self) -> RepeatedCompositeFieldContainer[TestParsingMerge.RepeatedFieldsGenerator.Group2]: ...
        @property
        def ext1(self) -> RepeatedCompositeFieldContainer[TestAllTypes]: ...
        @property
        def ext2(self) -> RepeatedCompositeFieldContainer[TestAllTypes]: ...
        def __init__(
            self,
            field1: Optional[Iterable[TestAllTypes]] = ...,
            field2: Optional[Iterable[TestAllTypes]] = ...,
            field3: Optional[Iterable[TestAllTypes]] = ...,
            group1: Optional[Iterable[TestParsingMerge.RepeatedFieldsGenerator.Group1]] = ...,
            group2: Optional[Iterable[TestParsingMerge.RepeatedFieldsGenerator.Group2]] = ...,
            ext1: Optional[Iterable[TestAllTypes]] = ...,
            ext2: Optional[Iterable[TestAllTypes]] = ...,
        ) -> None: ...
    class OptionalGroup(Message):
        @property
        def optional_group_all_types(self) -> TestAllTypes: ...
        def __init__(self, optional_group_all_types: Optional[TestAllTypes] = ...) -> None: ...
    class RepeatedGroup(Message):
        @property
        def repeated_group_all_types(self) -> TestAllTypes: ...
        def __init__(self, repeated_group_all_types: Optional[TestAllTypes] = ...) -> None: ...
    @property
    def required_all_types(self) -> TestAllTypes: ...
    @property
    def optional_all_types(self) -> TestAllTypes: ...
    @property
    def repeated_all_types(self) -> RepeatedCompositeFieldContainer[TestAllTypes]: ...
    @property
    def optionalgroup(self) -> TestParsingMerge.OptionalGroup: ...
    @property
    def repeatedgroup(self) -> RepeatedCompositeFieldContainer[TestParsingMerge.RepeatedGroup]: ...
    def __init__(
        self,
        required_all_types: TestAllTypes,
        optional_all_types: Optional[TestAllTypes] = ...,
        repeated_all_types: Optional[Iterable[TestAllTypes]] = ...,
        optionalgroup: Optional[TestParsingMerge.OptionalGroup] = ...,
        repeatedgroup: Optional[Iterable[TestParsingMerge.RepeatedGroup]] = ...,
    ) -> None: ...

class TestCommentInjectionMessage(Message):
    a: Text
    def __init__(self, a: Optional[Text] = ...) -> None: ...

class FooRequest(Message):
    def __init__(self,) -> None: ...

class FooResponse(Message):
    def __init__(self,) -> None: ...

class FooClientMessage(Message):
    def __init__(self,) -> None: ...

class FooServerMessage(Message):
    def __init__(self,) -> None: ...

class BarRequest(Message):
    def __init__(self,) -> None: ...

class BarResponse(Message):
    def __init__(self,) -> None: ...

class TestJsonName(Message):
    field_name1: int
    fieldName2: int
    FieldName3: int
    _field_name4: int
    FIELD_NAME5: int
    field_name6: int
    def __init__(
        self,
        field_name1: Optional[int] = ...,
        fieldName2: Optional[int] = ...,
        FieldName3: Optional[int] = ...,
        _field_name4: Optional[int] = ...,
        FIELD_NAME5: Optional[int] = ...,
        field_name6: Optional[int] = ...,
    ) -> None: ...

class TestHugeFieldNumbers(Message):
    class OptionalGroup(Message):
        group_a: int
        def __init__(self, group_a: Optional[int] = ...) -> None: ...
    class StringStringMapEntry(Message):
        key: Text
        value: Text
        def __init__(self, key: Optional[Text] = ..., value: Optional[Text] = ...) -> None: ...
    optional_int32: int
    fixed_32: int
    repeated_int32: RepeatedScalarFieldContainer[int]
    packed_int32: RepeatedScalarFieldContainer[int]
    optional_enum: ForeignEnum
    optional_string: Text
    optional_bytes: bytes
    oneof_uint32: int
    oneof_string: Text
    oneof_bytes: bytes
    @property
    def optional_message(self) -> ForeignMessage: ...
    @property
    def optionalgroup(self) -> TestHugeFieldNumbers.OptionalGroup: ...
    @property
    def string_string_map(self) -> MutableMapping[Text, Text]: ...
    @property
    def oneof_test_all_types(self) -> TestAllTypes: ...
    def __init__(
        self,
        optional_int32: Optional[int] = ...,
        fixed_32: Optional[int] = ...,
        repeated_int32: Optional[Iterable[int]] = ...,
        packed_int32: Optional[Iterable[int]] = ...,
        optional_enum: Optional[ForeignEnum] = ...,
        optional_string: Optional[Text] = ...,
        optional_bytes: Optional[bytes] = ...,
        optional_message: Optional[ForeignMessage] = ...,
        optionalgroup: Optional[TestHugeFieldNumbers.OptionalGroup] = ...,
        string_string_map: Optional[Mapping[Text, Text]] = ...,
        oneof_uint32: Optional[int] = ...,
        oneof_test_all_types: Optional[TestAllTypes] = ...,
        oneof_string: Optional[Text] = ...,
        oneof_bytes: Optional[bytes] = ...,
    ) -> None: ...

class TestExtensionInsideTable(Message):
    field1: int
    field2: int
    field3: int
    field4: int
    field6: int
    field7: int
    field8: int
    field9: int
    field10: int
    def __init__(
        self,
        field1: Optional[int] = ...,
        field2: Optional[int] = ...,
        field3: Optional[int] = ...,
        field4: Optional[int] = ...,
        field6: Optional[int] = ...,
        field7: Optional[int] = ...,
        field8: Optional[int] = ...,
        field9: Optional[int] = ...,
        field10: Optional[int] = ...,
    ) -> None: ...
