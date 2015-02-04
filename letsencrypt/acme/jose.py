"""JOSE."""
import base64
import binascii

import Crypto.PublicKey.RSA
import zope.interface

from letsencrypt.acme import interfaces


def _leading_zeros(arg):
    if len(arg) % 2:
        return '0' + arg
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
        return b64encode(binascii.unhexlify(
            _leading_zeros(hex(param)[2:].rstrip('L'))))

    @classmethod
    def _decode_param(cls, param):
        """Decode numeric key parameter."""
        return long(binascii.hexlify(b64decode(param)), 16)

    def to_json(self):
        """Serialize to JSON."""
        return {
            'kty': 'RSA',  # TODO
            'n': self._encode_param(self.key.n),
            'e': self._encode_param(self.key.e),
        }

    @classmethod
    def from_json(cls, jobj):
        """Deserialize from JSON."""
        assert 'RSA' == jobj['kty']  # TODO
        return cls(Crypto.PublicKey.RSA.construct(
            (cls._decode_param(jobj['n']), cls._decode_param(jobj['e']))))


# https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#appendix-C
#
# Jose Base64:
#
#   - URL-safe Base64
#
#   - padding stripped


def b64encode(data):
    """JOSE Base64 encode.

    :param data: Data to be encoded.
    :type data: str or bytearray

    :returns: JOSE Base64 string.
    :rtype: str

    :raises TypeError: if `data` is of incorrect type

    """
    if not isinstance(data, str):
        raise TypeError('argument should be str or bytearray')
    return base64.urlsafe_b64encode(data).rstrip('=')


def b64decode(data):
    """JOSE Base64 decode.

    :param data: Base64 string to be decoded. If it's unicode, then
                 only ASCII characters are allowed.
    :type data: str or unicode

    :returns: Decoded data.

    :raises TypeError: if input is of incorrect type
    :raises ValueError: if input is unicode with non-ASCII characters

    """
    if isinstance(data, unicode):
        try:
            data = data.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError(
                'unicode argument should contain only ASCII characters')
    elif not isinstance(data, str):
        raise TypeError('argument should be a str or unicode')

    return base64.urlsafe_b64decode(data + '=' * (4 - (len(data) % 4)))
