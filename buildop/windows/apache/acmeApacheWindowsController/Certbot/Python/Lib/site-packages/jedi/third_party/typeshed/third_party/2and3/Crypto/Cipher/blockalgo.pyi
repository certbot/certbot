from typing import Any, Union, Text

MODE_ECB: int
MODE_CBC: int
MODE_CFB: int
MODE_PGP: int
MODE_OFB: int
MODE_CTR: int
MODE_OPENPGP: int

class BlockAlgo:
    mode: int
    block_size: int
    IV: Any
    def __init__(self, factory: Any, key: Union[bytes, Text], *args, **kwargs) -> None: ...
    def encrypt(self, plaintext: Union[bytes, Text]) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...
