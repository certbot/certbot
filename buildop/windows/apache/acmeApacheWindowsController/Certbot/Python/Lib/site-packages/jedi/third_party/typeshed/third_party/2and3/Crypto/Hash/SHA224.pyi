from typing import Any, Optional
from Crypto.Hash.hashalgo import HashAlgo

class SHA224Hash(HashAlgo):
    oid: Any
    digest_size: int
    block_size: int
    def __init__(self, data: Optional[Any] = ...) -> None: ...
    def new(self, data: Optional[Any] = ...): ...

def new(data: Optional[Any] = ...): ...

digest_size: Any
