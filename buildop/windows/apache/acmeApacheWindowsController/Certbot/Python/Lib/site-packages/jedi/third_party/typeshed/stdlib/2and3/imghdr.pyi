from typing import overload, Union, Text, BinaryIO, Optional, Any, List, Callable
import sys
import os


if sys.version_info >= (3, 6):
    _File = Union[Text, os.PathLike[Text], BinaryIO]
else:
    _File = Union[Text, BinaryIO]


@overload
def what(file: _File) -> Optional[str]: ...
@overload
def what(file: Any, h: bytes) -> Optional[str]: ...
tests: List[Callable[[bytes, BinaryIO], Optional[str]]]
