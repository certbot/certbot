from typing import Any

__revision__: str

class AESGenerator:
    block_size: Any
    key_size: int
    max_blocks_per_request: Any
    counter: Any
    key: Any
    block_size_shift: Any
    blocks_per_key: Any
    max_bytes_per_request: Any
    def __init__(self) -> None: ...
    def reseed(self, seed): ...
    def pseudo_random_data(self, bytes): ...
