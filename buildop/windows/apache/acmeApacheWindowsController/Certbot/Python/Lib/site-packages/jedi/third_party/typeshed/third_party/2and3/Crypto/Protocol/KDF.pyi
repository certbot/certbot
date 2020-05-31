from typing import Any, Optional
from Crypto.Hash import SHA as SHA1

__revision__: str

def PBKDF1(password, salt, dkLen, count: int = ..., hashAlgo: Optional[Any] = ...): ...
def PBKDF2(password, salt, dkLen: int = ..., count: int = ..., prf: Optional[Any] = ...): ...
