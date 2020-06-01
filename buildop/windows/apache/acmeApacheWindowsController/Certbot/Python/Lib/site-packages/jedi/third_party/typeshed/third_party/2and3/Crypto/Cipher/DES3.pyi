from typing import Any, Union, Text

from .blockalgo import BlockAlgo

__revision__: str

class DES3Cipher(BlockAlgo):
    def __init__(self, key: Union[bytes, Text], *args, **kwargs) -> None: ...

def new(key: Union[bytes, Text], *args, **kwargs) -> DES3Cipher: ...

MODE_ECB: int
MODE_CBC: int
MODE_CFB: int
MODE_PGP: int
MODE_OFB: int
MODE_CTR: int
MODE_OPENPGP: int
block_size: int
key_size: Any
