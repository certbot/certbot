from typing import Any
from jwt.algorithms import Algorithm

from . import _HashAlg

class ECAlgorithm(Algorithm[Any]):
    SHA256: _HashAlg
    SHA384: _HashAlg
    SHA512: _HashAlg
    def __init__(self, hash_alg: _HashAlg) -> None: ...
