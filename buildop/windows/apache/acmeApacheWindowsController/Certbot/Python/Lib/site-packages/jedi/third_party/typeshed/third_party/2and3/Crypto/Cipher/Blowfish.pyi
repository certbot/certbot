from typing import Any, Union, Text
from .blockalgo import BlockAlgo

__revision__: str

class BlowfishCipher(BlockAlgo):
    def __init__(self, key: Union[bytes, Text], *args, **kwargs) -> None: ...

def new(key: Union[bytes, Text], *args, **kwargs) -> BlowfishCipher: ...

MODE_ECB: int
MODE_CBC: int
MODE_CFB: int
MODE_PGP: int
MODE_OFB: int
MODE_CTR: int
MODE_OPENPGP: int
block_size: int
key_size: Any
