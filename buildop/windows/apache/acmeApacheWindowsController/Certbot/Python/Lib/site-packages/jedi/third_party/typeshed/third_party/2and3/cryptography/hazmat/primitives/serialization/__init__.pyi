from abc import ABCMeta
from enum import Enum
from typing import Optional

def load_pem_private_key(data: bytes, password: Optional[bytes], backend): ...
def load_pem_public_key(data: bytes, backend): ...
def load_der_private_key(data: bytes, password: Optional[bytes], backend): ...
def load_der_public_key(data: bytes, backend): ...
def load_ssh_public_key(data: bytes, backend): ...

class Encoding(Enum):
    PEM: str
    DER: str
    OpenSSH: str
    Raw: str
    X962: str

class PrivateFormat(Enum):
    PKCS8: str
    TraditionalOpenSSL: str
    Raw: str

class PublicFormat(Enum):
    SubjectPublicKeyInfo: str
    PKCS1: str
    OpenSSH: str
    Raw: str
    CompressedPoint: str
    UncompressedPoint: str

class ParameterFormat(Enum):
    PKCS3: str

class KeySerializationEncryption(metaclass=ABCMeta): ...

class BestAvailableEncryption(KeySerializationEncryption):
    password: bytes
    def __init__(self, password: bytes) -> None: ...

class NoEncryption(KeySerializationEncryption): ...
