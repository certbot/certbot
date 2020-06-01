from google.protobuf.any_pb2 import Any
from google.protobuf.internal.containers import RepeatedCompositeFieldContainer, RepeatedScalarFieldContainer
from google.protobuf.message import Message
from google.protobuf.source_context_pb2 import SourceContext
from typing import Iterable, List, Optional, Text, Tuple, cast

class Syntax(int):
    @classmethod
    def Name(cls, number: int) -> bytes: ...
    @classmethod
    def Value(cls, name: bytes) -> Syntax: ...
    @classmethod
    def keys(cls) -> List[bytes]: ...
    @classmethod
    def values(cls) -> List[Syntax]: ...
    @classmethod
    def items(cls) -> List[Tuple[bytes, Syntax]]: ...

SYNTAX_PROTO2: Syntax
SYNTAX_PROTO3: Syntax

class Type(Message):
    name: Text
    oneofs: RepeatedScalarFieldContainer[Text]
    syntax: Syntax
    @property
    def fields(self) -> RepeatedCompositeFieldContainer[Field]: ...
    @property
    def options(self) -> RepeatedCompositeFieldContainer[Option]: ...
    @property
    def source_context(self) -> SourceContext: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        fields: Optional[Iterable[Field]] = ...,
        oneofs: Optional[Iterable[Text]] = ...,
        options: Optional[Iterable[Option]] = ...,
        source_context: Optional[SourceContext] = ...,
        syntax: Optional[Syntax] = ...,
    ) -> None: ...

class Field(Message):
    class Kind(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> Field.Kind: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[Field.Kind]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, Field.Kind]]: ...
    TYPE_UNKNOWN: Field.Kind
    TYPE_DOUBLE: Field.Kind
    TYPE_FLOAT: Field.Kind
    TYPE_INT64: Field.Kind
    TYPE_UINT64: Field.Kind
    TYPE_INT32: Field.Kind
    TYPE_FIXED64: Field.Kind
    TYPE_FIXED32: Field.Kind
    TYPE_BOOL: Field.Kind
    TYPE_STRING: Field.Kind
    TYPE_GROUP: Field.Kind
    TYPE_MESSAGE: Field.Kind
    TYPE_BYTES: Field.Kind
    TYPE_UINT32: Field.Kind
    TYPE_ENUM: Field.Kind
    TYPE_SFIXED32: Field.Kind
    TYPE_SFIXED64: Field.Kind
    TYPE_SINT32: Field.Kind
    TYPE_SINT64: Field.Kind
    class Cardinality(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> Field.Cardinality: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[Field.Cardinality]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, Field.Cardinality]]: ...
    CARDINALITY_UNKNOWN: Field.Cardinality
    CARDINALITY_OPTIONAL: Field.Cardinality
    CARDINALITY_REQUIRED: Field.Cardinality
    CARDINALITY_REPEATED: Field.Cardinality
    kind: Field.Kind
    cardinality: Field.Cardinality
    number: int
    name: Text
    type_url: Text
    oneof_index: int
    packed: bool
    json_name: Text
    default_value: Text
    @property
    def options(self) -> RepeatedCompositeFieldContainer[Option]: ...
    def __init__(
        self,
        kind: Optional[Field.Kind] = ...,
        cardinality: Optional[Field.Cardinality] = ...,
        number: Optional[int] = ...,
        name: Optional[Text] = ...,
        type_url: Optional[Text] = ...,
        oneof_index: Optional[int] = ...,
        packed: Optional[bool] = ...,
        options: Optional[Iterable[Option]] = ...,
        json_name: Optional[Text] = ...,
        default_value: Optional[Text] = ...,
    ) -> None: ...

class Enum(Message):
    name: Text
    syntax: Syntax
    @property
    def enumvalue(self) -> RepeatedCompositeFieldContainer[EnumValue]: ...
    @property
    def options(self) -> RepeatedCompositeFieldContainer[Option]: ...
    @property
    def source_context(self) -> SourceContext: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        enumvalue: Optional[Iterable[EnumValue]] = ...,
        options: Optional[Iterable[Option]] = ...,
        source_context: Optional[SourceContext] = ...,
        syntax: Optional[Syntax] = ...,
    ) -> None: ...

class EnumValue(Message):
    name: Text
    number: int
    @property
    def options(self) -> RepeatedCompositeFieldContainer[Option]: ...
    def __init__(
        self, name: Optional[Text] = ..., number: Optional[int] = ..., options: Optional[Iterable[Option]] = ...
    ) -> None: ...

class Option(Message):
    name: Text
    @property
    def value(self) -> Any: ...
    def __init__(self, name: Optional[Text] = ..., value: Optional[Any] = ...) -> None: ...
