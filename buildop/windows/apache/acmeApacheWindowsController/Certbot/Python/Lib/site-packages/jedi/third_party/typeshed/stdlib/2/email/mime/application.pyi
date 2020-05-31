# Stubs for email.mime.application

from typing import Callable, Optional, Tuple, Union
from email.mime.nonmultipart import MIMENonMultipart

_ParamsType = Union[str, None, Tuple[str, Optional[str], str]]

class MIMEApplication(MIMENonMultipart):
    def __init__(self, _data: bytes, _subtype: str = ...,
                 _encoder: Callable[[MIMEApplication], None] = ...,
                 **_params: _ParamsType) -> None: ...
