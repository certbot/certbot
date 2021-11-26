"""
Certificate Mappings
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List

class CertType(Enum):
    """Valid certificate types"""

    CHAIN = "chain"
    FULL_CHAIN = "fullchain"
    PRIVATE_KEY = "privkey"
    CERTIFICATE = "cert"

@dataclass
class CertMapping:
    """Class for keeping track of the mappings between a consul key and its cert contents"""

    key: str
    contents: List[CertType] = field(default_factory=list)
