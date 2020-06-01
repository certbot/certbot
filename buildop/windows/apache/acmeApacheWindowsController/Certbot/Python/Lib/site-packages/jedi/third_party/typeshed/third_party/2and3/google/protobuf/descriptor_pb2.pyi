from google.protobuf.internal.containers import RepeatedCompositeFieldContainer, RepeatedScalarFieldContainer
from google.protobuf.message import Message
from typing import Iterable, List, Optional, Text, Tuple, cast

class FileDescriptorSet(Message):
    @property
    def file(self) -> RepeatedCompositeFieldContainer[FileDescriptorProto]: ...
    def __init__(self, file: Optional[Iterable[FileDescriptorProto]] = ...) -> None: ...

class FileDescriptorProto(Message):
    name: Text
    package: Text
    dependency: RepeatedScalarFieldContainer[Text]
    public_dependency: RepeatedScalarFieldContainer[int]
    weak_dependency: RepeatedScalarFieldContainer[int]
    syntax: Text
    @property
    def message_type(self) -> RepeatedCompositeFieldContainer[DescriptorProto]: ...
    @property
    def enum_type(self) -> RepeatedCompositeFieldContainer[EnumDescriptorProto]: ...
    @property
    def service(self) -> RepeatedCompositeFieldContainer[ServiceDescriptorProto]: ...
    @property
    def extension(self) -> RepeatedCompositeFieldContainer[FieldDescriptorProto]: ...
    @property
    def options(self) -> FileOptions: ...
    @property
    def source_code_info(self) -> SourceCodeInfo: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        package: Optional[Text] = ...,
        dependency: Optional[Iterable[Text]] = ...,
        public_dependency: Optional[Iterable[int]] = ...,
        weak_dependency: Optional[Iterable[int]] = ...,
        message_type: Optional[Iterable[DescriptorProto]] = ...,
        enum_type: Optional[Iterable[EnumDescriptorProto]] = ...,
        service: Optional[Iterable[ServiceDescriptorProto]] = ...,
        extension: Optional[Iterable[FieldDescriptorProto]] = ...,
        options: Optional[FileOptions] = ...,
        source_code_info: Optional[SourceCodeInfo] = ...,
        syntax: Optional[Text] = ...,
    ) -> None: ...

class DescriptorProto(Message):
    class ExtensionRange(Message):
        start: int
        end: int
        @property
        def options(self) -> ExtensionRangeOptions: ...
        def __init__(
            self, start: Optional[int] = ..., end: Optional[int] = ..., options: Optional[ExtensionRangeOptions] = ...
        ) -> None: ...
    class ReservedRange(Message):
        start: int
        end: int
        def __init__(self, start: Optional[int] = ..., end: Optional[int] = ...) -> None: ...
    name: Text
    reserved_name: RepeatedScalarFieldContainer[Text]
    @property
    def field(self) -> RepeatedCompositeFieldContainer[FieldDescriptorProto]: ...
    @property
    def extension(self) -> RepeatedCompositeFieldContainer[FieldDescriptorProto]: ...
    @property
    def nested_type(self) -> RepeatedCompositeFieldContainer[DescriptorProto]: ...
    @property
    def enum_type(self) -> RepeatedCompositeFieldContainer[EnumDescriptorProto]: ...
    @property
    def extension_range(self) -> RepeatedCompositeFieldContainer[DescriptorProto.ExtensionRange]: ...
    @property
    def oneof_decl(self) -> RepeatedCompositeFieldContainer[OneofDescriptorProto]: ...
    @property
    def options(self) -> MessageOptions: ...
    @property
    def reserved_range(self) -> RepeatedCompositeFieldContainer[DescriptorProto.ReservedRange]: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        field: Optional[Iterable[FieldDescriptorProto]] = ...,
        extension: Optional[Iterable[FieldDescriptorProto]] = ...,
        nested_type: Optional[Iterable[DescriptorProto]] = ...,
        enum_type: Optional[Iterable[EnumDescriptorProto]] = ...,
        extension_range: Optional[Iterable[DescriptorProto.ExtensionRange]] = ...,
        oneof_decl: Optional[Iterable[OneofDescriptorProto]] = ...,
        options: Optional[MessageOptions] = ...,
        reserved_range: Optional[Iterable[DescriptorProto.ReservedRange]] = ...,
        reserved_name: Optional[Iterable[Text]] = ...,
    ) -> None: ...

class ExtensionRangeOptions(Message):
    @property
    def uninterpreted_option(self) -> RepeatedCompositeFieldContainer[UninterpretedOption]: ...
    def __init__(self, uninterpreted_option: Optional[Iterable[UninterpretedOption]] = ...) -> None: ...

class FieldDescriptorProto(Message):
    class Type(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> FieldDescriptorProto.Type: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[FieldDescriptorProto.Type]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, FieldDescriptorProto.Type]]: ...
    TYPE_DOUBLE: FieldDescriptorProto.Type
    TYPE_FLOAT: FieldDescriptorProto.Type
    TYPE_INT64: FieldDescriptorProto.Type
    TYPE_UINT64: FieldDescriptorProto.Type
    TYPE_INT32: FieldDescriptorProto.Type
    TYPE_FIXED64: FieldDescriptorProto.Type
    TYPE_FIXED32: FieldDescriptorProto.Type
    TYPE_BOOL: FieldDescriptorProto.Type
    TYPE_STRING: FieldDescriptorProto.Type
    TYPE_GROUP: FieldDescriptorProto.Type
    TYPE_MESSAGE: FieldDescriptorProto.Type
    TYPE_BYTES: FieldDescriptorProto.Type
    TYPE_UINT32: FieldDescriptorProto.Type
    TYPE_ENUM: FieldDescriptorProto.Type
    TYPE_SFIXED32: FieldDescriptorProto.Type
    TYPE_SFIXED64: FieldDescriptorProto.Type
    TYPE_SINT32: FieldDescriptorProto.Type
    TYPE_SINT64: FieldDescriptorProto.Type
    class Label(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> FieldDescriptorProto.Label: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[FieldDescriptorProto.Label]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, FieldDescriptorProto.Label]]: ...
    LABEL_OPTIONAL: FieldDescriptorProto.Label
    LABEL_REQUIRED: FieldDescriptorProto.Label
    LABEL_REPEATED: FieldDescriptorProto.Label
    name: Text
    number: int
    label: FieldDescriptorProto.Label
    type: FieldDescriptorProto.Type
    type_name: Text
    extendee: Text
    default_value: Text
    oneof_index: int
    json_name: Text
    @property
    def options(self) -> FieldOptions: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        number: Optional[int] = ...,
        label: Optional[FieldDescriptorProto.Label] = ...,
        type: Optional[FieldDescriptorProto.Type] = ...,
        type_name: Optional[Text] = ...,
        extendee: Optional[Text] = ...,
        default_value: Optional[Text] = ...,
        oneof_index: Optional[int] = ...,
        json_name: Optional[Text] = ...,
        options: Optional[FieldOptions] = ...,
    ) -> None: ...

class OneofDescriptorProto(Message):
    name: Text
    @property
    def options(self) -> OneofOptions: ...
    def __init__(self, name: Optional[Text] = ..., options: Optional[OneofOptions] = ...) -> None: ...

class EnumDescriptorProto(Message):
    class EnumReservedRange(Message):
        start: int
        end: int
        def __init__(self, start: Optional[int] = ..., end: Optional[int] = ...) -> None: ...
    name: Text
    reserved_name: RepeatedScalarFieldContainer[Text]
    @property
    def value(self) -> RepeatedCompositeFieldContainer[EnumValueDescriptorProto]: ...
    @property
    def options(self) -> EnumOptions: ...
    @property
    def reserved_range(self) -> RepeatedCompositeFieldContainer[EnumDescriptorProto.EnumReservedRange]: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        value: Optional[Iterable[EnumValueDescriptorProto]] = ...,
        options: Optional[EnumOptions] = ...,
        reserved_range: Optional[Iterable[EnumDescriptorProto.EnumReservedRange]] = ...,
        reserved_name: Optional[Iterable[Text]] = ...,
    ) -> None: ...

class EnumValueDescriptorProto(Message):
    name: Text
    number: int
    @property
    def options(self) -> EnumValueOptions: ...
    def __init__(
        self, name: Optional[Text] = ..., number: Optional[int] = ..., options: Optional[EnumValueOptions] = ...
    ) -> None: ...

class ServiceDescriptorProto(Message):
    name: Text
    @property
    def method(self) -> RepeatedCompositeFieldContainer[MethodDescriptorProto]: ...
    @property
    def options(self) -> ServiceOptions: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        method: Optional[Iterable[MethodDescriptorProto]] = ...,
        options: Optional[ServiceOptions] = ...,
    ) -> None: ...

class MethodDescriptorProto(Message):
    name: Text
    input_type: Text
    output_type: Text
    client_streaming: bool
    server_streaming: bool
    @property
    def options(self) -> MethodOptions: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        input_type: Optional[Text] = ...,
        output_type: Optional[Text] = ...,
        options: Optional[MethodOptions] = ...,
        client_streaming: Optional[bool] = ...,
        server_streaming: Optional[bool] = ...,
    ) -> None: ...

class FileOptions(Message):
    class OptimizeMode(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> FileOptions.OptimizeMode: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[FileOptions.OptimizeMode]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, FileOptions.OptimizeMode]]: ...
    SPEED: FileOptions.OptimizeMode
    CODE_SIZE: FileOptions.OptimizeMode
    LITE_RUNTIME: FileOptions.OptimizeMode
    java_package: Text
    java_outer_classname: Text
    java_multiple_files: bool
    java_generate_equals_and_hash: bool
    java_string_check_utf8: bool
    optimize_for: FileOptions.OptimizeMode
    go_package: Text
    cc_generic_services: bool
    java_generic_services: bool
    py_generic_services: bool
    php_generic_services: bool
    deprecated: bool
    cc_enable_arenas: bool
    objc_class_prefix: Text
    csharp_namespace: Text
    swift_prefix: Text
    php_class_prefix: Text
    php_namespace: Text
    @property
    def uninterpreted_option(self) -> RepeatedCompositeFieldContainer[UninterpretedOption]: ...
    def __init__(
        self,
        java_package: Optional[Text] = ...,
        java_outer_classname: Optional[Text] = ...,
        java_multiple_files: Optional[bool] = ...,
        java_generate_equals_and_hash: Optional[bool] = ...,
        java_string_check_utf8: Optional[bool] = ...,
        optimize_for: Optional[FileOptions.OptimizeMode] = ...,
        go_package: Optional[Text] = ...,
        cc_generic_services: Optional[bool] = ...,
        java_generic_services: Optional[bool] = ...,
        py_generic_services: Optional[bool] = ...,
        php_generic_services: Optional[bool] = ...,
        deprecated: Optional[bool] = ...,
        cc_enable_arenas: Optional[bool] = ...,
        objc_class_prefix: Optional[Text] = ...,
        csharp_namespace: Optional[Text] = ...,
        swift_prefix: Optional[Text] = ...,
        php_class_prefix: Optional[Text] = ...,
        php_namespace: Optional[Text] = ...,
        uninterpreted_option: Optional[Iterable[UninterpretedOption]] = ...,
    ) -> None: ...

class MessageOptions(Message):
    message_set_wire_format: bool
    no_standard_descriptor_accessor: bool
    deprecated: bool
    map_entry: bool
    @property
    def uninterpreted_option(self) -> RepeatedCompositeFieldContainer[UninterpretedOption]: ...
    def __init__(
        self,
        message_set_wire_format: Optional[bool] = ...,
        no_standard_descriptor_accessor: Optional[bool] = ...,
        deprecated: Optional[bool] = ...,
        map_entry: Optional[bool] = ...,
        uninterpreted_option: Optional[Iterable[UninterpretedOption]] = ...,
    ) -> None: ...

class FieldOptions(Message):
    class CType(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> FieldOptions.CType: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[FieldOptions.CType]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, FieldOptions.CType]]: ...
    STRING: FieldOptions.CType
    CORD: FieldOptions.CType
    STRING_PIECE: FieldOptions.CType
    class JSType(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> FieldOptions.JSType: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[FieldOptions.JSType]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, FieldOptions.JSType]]: ...
    JS_NORMAL: FieldOptions.JSType
    JS_STRING: FieldOptions.JSType
    JS_NUMBER: FieldOptions.JSType
    ctype: FieldOptions.CType
    packed: bool
    jstype: FieldOptions.JSType
    lazy: bool
    deprecated: bool
    weak: bool
    @property
    def uninterpreted_option(self) -> RepeatedCompositeFieldContainer[UninterpretedOption]: ...
    def __init__(
        self,
        ctype: Optional[FieldOptions.CType] = ...,
        packed: Optional[bool] = ...,
        jstype: Optional[FieldOptions.JSType] = ...,
        lazy: Optional[bool] = ...,
        deprecated: Optional[bool] = ...,
        weak: Optional[bool] = ...,
        uninterpreted_option: Optional[Iterable[UninterpretedOption]] = ...,
    ) -> None: ...

class OneofOptions(Message):
    @property
    def uninterpreted_option(self) -> RepeatedCompositeFieldContainer[UninterpretedOption]: ...
    def __init__(self, uninterpreted_option: Optional[Iterable[UninterpretedOption]] = ...) -> None: ...

class EnumOptions(Message):
    allow_alias: bool
    deprecated: bool
    @property
    def uninterpreted_option(self) -> RepeatedCompositeFieldContainer[UninterpretedOption]: ...
    def __init__(
        self,
        allow_alias: Optional[bool] = ...,
        deprecated: Optional[bool] = ...,
        uninterpreted_option: Optional[Iterable[UninterpretedOption]] = ...,
    ) -> None: ...

class EnumValueOptions(Message):
    deprecated: bool
    @property
    def uninterpreted_option(self) -> RepeatedCompositeFieldContainer[UninterpretedOption]: ...
    def __init__(
        self, deprecated: Optional[bool] = ..., uninterpreted_option: Optional[Iterable[UninterpretedOption]] = ...
    ) -> None: ...

class ServiceOptions(Message):
    deprecated: bool
    @property
    def uninterpreted_option(self) -> RepeatedCompositeFieldContainer[UninterpretedOption]: ...
    def __init__(
        self, deprecated: Optional[bool] = ..., uninterpreted_option: Optional[Iterable[UninterpretedOption]] = ...
    ) -> None: ...

class MethodOptions(Message):
    class IdempotencyLevel(int):
        @classmethod
        def Name(cls, number: int) -> bytes: ...
        @classmethod
        def Value(cls, name: bytes) -> MethodOptions.IdempotencyLevel: ...
        @classmethod
        def keys(cls) -> List[bytes]: ...
        @classmethod
        def values(cls) -> List[MethodOptions.IdempotencyLevel]: ...
        @classmethod
        def items(cls) -> List[Tuple[bytes, MethodOptions.IdempotencyLevel]]: ...
    IDEMPOTENCY_UNKNOWN: MethodOptions.IdempotencyLevel
    NO_SIDE_EFFECTS: MethodOptions.IdempotencyLevel
    IDEMPOTENT: MethodOptions.IdempotencyLevel
    deprecated: bool
    idempotency_level: MethodOptions.IdempotencyLevel
    @property
    def uninterpreted_option(self) -> RepeatedCompositeFieldContainer[UninterpretedOption]: ...
    def __init__(
        self,
        deprecated: Optional[bool] = ...,
        idempotency_level: Optional[MethodOptions.IdempotencyLevel] = ...,
        uninterpreted_option: Optional[Iterable[UninterpretedOption]] = ...,
    ) -> None: ...

class UninterpretedOption(Message):
    class NamePart(Message):
        name_part: Text
        is_extension: bool
        def __init__(self, name_part: Text, is_extension: bool) -> None: ...
    identifier_value: Text
    positive_int_value: int
    negative_int_value: int
    double_value: float
    string_value: bytes
    aggregate_value: Text
    @property
    def name(self) -> RepeatedCompositeFieldContainer[UninterpretedOption.NamePart]: ...
    def __init__(
        self,
        name: Optional[Iterable[UninterpretedOption.NamePart]] = ...,
        identifier_value: Optional[Text] = ...,
        positive_int_value: Optional[int] = ...,
        negative_int_value: Optional[int] = ...,
        double_value: Optional[float] = ...,
        string_value: Optional[bytes] = ...,
        aggregate_value: Optional[Text] = ...,
    ) -> None: ...

class SourceCodeInfo(Message):
    class Location(Message):
        path: RepeatedScalarFieldContainer[int]
        span: RepeatedScalarFieldContainer[int]
        leading_comments: Text
        trailing_comments: Text
        leading_detached_comments: RepeatedScalarFieldContainer[Text]
        def __init__(
            self,
            path: Optional[Iterable[int]] = ...,
            span: Optional[Iterable[int]] = ...,
            leading_comments: Optional[Text] = ...,
            trailing_comments: Optional[Text] = ...,
            leading_detached_comments: Optional[Iterable[Text]] = ...,
        ) -> None: ...
    @property
    def location(self) -> RepeatedCompositeFieldContainer[SourceCodeInfo.Location]: ...
    def __init__(self, location: Optional[Iterable[SourceCodeInfo.Location]] = ...) -> None: ...

class GeneratedCodeInfo(Message):
    class Annotation(Message):
        path: RepeatedScalarFieldContainer[int]
        source_file: Text
        begin: int
        end: int
        def __init__(
            self,
            path: Optional[Iterable[int]] = ...,
            source_file: Optional[Text] = ...,
            begin: Optional[int] = ...,
            end: Optional[int] = ...,
        ) -> None: ...
    @property
    def annotation(self) -> RepeatedCompositeFieldContainer[GeneratedCodeInfo.Annotation]: ...
    def __init__(self, annotation: Optional[Iterable[GeneratedCodeInfo.Annotation]] = ...) -> None: ...
