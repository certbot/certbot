# Stubs for email.mime.image (Python 3.4)

from typing import Callable, Optional, Tuple, Union
from email.mime.nonmultipart import MIMENonMultipart

_ParamsType = Union[str, None, Tuple[str, Optional[str], str]]

class MIMEImage(MIMENonMultipart):
    def __init__(self, _imagedata: Union[str, bytes], _subtype: Optional[str] = ...,
                 _encoder: Callable[[MIMEImage], None] = ...,
                 **_params: _ParamsType) -> None: ...
