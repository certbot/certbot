"""JOSE."""
import binascii
import zope.interface

import Crypto.PublicKey.RSA

from letsencrypt.acme import interfaces
from letsencrypt.client import le_util


def _leading_zeros(arg):
    if len(arg) % 2:
        return "0" + arg
    return arg


class JWK(object):
    """JSON Web Key.

    .. todo:: Currently works for RSA keys only.

    """
    zope.interface.implements(interfaces.IJSONSerializable)

    def __init__(self, key):
        self.key = key

    def __eq__(self, other):
        if isinstance(other, JWK):
            return self.key == other.key
        else:
            raise TypeError(
                'Unable to compare JWK object with: {0}'.format(other))

    def same_public_key(self, other):
        """Does ``other`` have the same public key?"""
        if isinstance(other, JWK):
            return self.key.publickey() == other.key.publickey()
        else:
            raise TypeError(
                'Unable to compare JWK object with: {0}'.format(other))

    @classmethod
    def _encode_param(cls, param):
        """Encode numeric key parameter."""
        return le_util.jose_b64encode(binascii.unhexlify(
            _leading_zeros(hex(param)[2:].rstrip("L"))))

    @classmethod
    def _decode_param(cls, param):
        """Decode numeric key parameter."""
        return long(binascii.hexlify(le_util.jose_b64decode(param)), 16)

    def to_json(self):
        """Serialize to JSON."""
        return {
            "kty": "RSA",  # TODO
            "n": self._encode_param(self.key.n),
            "e": self._encode_param(self.key.e),
        }

    @classmethod
    def from_json(cls, json_object):
        """Deserialize from JSON."""
        assert "RSA" == json_object["kty"]  # TODO
        return cls(Crypto.PublicKey.RSA.construct(
            (cls._decode_param(json_object["n"]),
             cls._decode_param(json_object["e"]))))
