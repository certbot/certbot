from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from google.protobuf.message import Message
from google.protobuf.source_context_pb2 import SourceContext
from google.protobuf.type_pb2 import Option, Syntax
from typing import Iterable, Optional, Text

class Api(Message):
    name: Text
    version: Text
    syntax: Syntax
    @property
    def methods(self) -> RepeatedCompositeFieldContainer[Method]: ...
    @property
    def options(self) -> RepeatedCompositeFieldContainer[Option]: ...
    @property
    def source_context(self) -> SourceContext: ...
    @property
    def mixins(self) -> RepeatedCompositeFieldContainer[Mixin]: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        methods: Optional[Iterable[Method]] = ...,
        options: Optional[Iterable[Option]] = ...,
        version: Optional[Text] = ...,
        source_context: Optional[SourceContext] = ...,
        mixins: Optional[Iterable[Mixin]] = ...,
        syntax: Optional[Syntax] = ...,
    ) -> None: ...

class Method(Message):
    name: Text
    request_type_url: Text
    request_streaming: bool
    response_type_url: Text
    response_streaming: bool
    syntax: Syntax
    @property
    def options(self) -> RepeatedCompositeFieldContainer[Option]: ...
    def __init__(
        self,
        name: Optional[Text] = ...,
        request_type_url: Optional[Text] = ...,
        request_streaming: Optional[bool] = ...,
        response_type_url: Optional[Text] = ...,
        response_streaming: Optional[bool] = ...,
        options: Optional[Iterable[Option]] = ...,
        syntax: Optional[Syntax] = ...,
    ) -> None: ...

class Mixin(Message):
    name: Text
    root: Text
    def __init__(self, name: Optional[Text] = ..., root: Optional[Text] = ...) -> None: ...
