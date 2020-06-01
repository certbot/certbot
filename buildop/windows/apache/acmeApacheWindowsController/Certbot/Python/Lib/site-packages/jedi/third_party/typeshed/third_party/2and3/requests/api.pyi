# Stubs for requests.api (Python 3)

import sys
from typing import Optional, Union, Any, Iterable, Mapping, MutableMapping, Tuple, IO, Text

from .models import Response
from .sessions import _Data

_ParamsMappingValueType = Union[Text, bytes, int, float, Iterable[Union[Text, bytes, int, float]]]

def request(method: str, url: str, **kwargs) -> Response: ...
def get(
    url: Union[Text, bytes],
    params: Optional[
        Union[
            Mapping[Union[Text, bytes, int, float], _ParamsMappingValueType],
            Union[Text, bytes],
            Tuple[Union[Text, bytes, int, float], _ParamsMappingValueType],
            Mapping[Text, _ParamsMappingValueType],
            Mapping[bytes, _ParamsMappingValueType],
            Mapping[int, _ParamsMappingValueType],
            Mapping[float, _ParamsMappingValueType],
        ]
    ] = ...,
    **kwargs,
) -> Response: ...
def options(url: Union[Text, bytes], **kwargs) -> Response: ...
def head(url: Union[Text, bytes], **kwargs) -> Response: ...
def post(url: Union[Text, bytes], data: _Data = ..., json=..., **kwargs) -> Response: ...
def put(url: Union[Text, bytes], data: _Data = ..., json=..., **kwargs) -> Response: ...
def patch(url: Union[Text, bytes], data: _Data = ..., json=..., **kwargs) -> Response: ...
def delete(url: Union[Text, bytes], **kwargs) -> Response: ...
