# Stubs for hashlib

import sys
from typing import AbstractSet, Optional, Union

_DataType = Union[bytes, bytearray, memoryview]

class _Hash(object):
    digest_size: int
    block_size: int

    # [Python documentation note] Changed in version 3.4: The name attribute has
    # been present in CPython since its inception, but until Python 3.4 was not
    # formally specified, so may not exist on some platforms
    name: str

    def __init__(self, data: _DataType = ...) -> None: ...

    def copy(self) -> _Hash: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def update(self, arg: _DataType) -> None: ...

def md5(arg: _DataType = ...) -> _Hash: ...
def sha1(arg: _DataType = ...) -> _Hash: ...
def sha224(arg: _DataType = ...) -> _Hash: ...
def sha256(arg: _DataType = ...) -> _Hash: ...
def sha384(arg: _DataType = ...) -> _Hash: ...
def sha512(arg: _DataType = ...) -> _Hash: ...

def new(name: str, data: _DataType = ...) -> _Hash: ...

algorithms_guaranteed: AbstractSet[str]
algorithms_available: AbstractSet[str]

def pbkdf2_hmac(hash_name: str, password: _DataType, salt: _DataType, iterations: int, dklen: Optional[int] = ...) -> bytes: ...

if sys.version_info >= (3, 6):
    class _VarLenHash(object):
        digest_size: int
        block_size: int
        name: str

        def __init__(self, data: _DataType = ...) -> None: ...

        def copy(self) -> _VarLenHash: ...
        def digest(self, length: int) -> bytes: ...
        def hexdigest(self, length: int) -> str: ...
        def update(self, arg: _DataType) -> None: ...

    sha3_224 = _Hash
    sha3_256 = _Hash
    sha3_384 = _Hash
    sha3_512 = _Hash
    shake_128 = _VarLenHash
    shake_256 = _VarLenHash

    def scrypt(password: _DataType, *, salt: _DataType, n: int, r: int, p: int, maxmem: int = ..., dklen: int = ...) -> bytes: ...

    class _BlakeHash(_Hash):
        MAX_DIGEST_SIZE: int
        MAX_KEY_SIZE: int
        PERSON_SIZE: int
        SALT_SIZE: int

        def __init__(self, data: _DataType = ..., digest_size: int = ..., key: _DataType = ..., salt: _DataType = ..., person: _DataType = ..., fanout: int = ..., depth: int = ..., leaf_size: int = ..., node_offset: int = ..., node_depth: int = ..., inner_size: int = ..., last_node: bool = ...) -> None: ...

    blake2b = _BlakeHash
    blake2s = _BlakeHash
