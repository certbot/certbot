# Stubs for email.mime.base (Python 3.4)

from typing import Optional, Tuple, Union
import email.message

_ParamsType = Union[str, None, Tuple[str, Optional[str], str]]

class MIMEBase(email.message.Message):
    def __init__(self, _maintype: str, _subtype: str,
                 **_params: _ParamsType) -> None: ...
