"""JSON Web Key."""
import binascii

import Crypto.PublicKey.RSA

from letsencrypt.acme.jose import b64
from letsencrypt.acme.jose import errors
from letsencrypt.acme.jose import json_util


class JWK(json_util.TypedJSONObjectWithFields):
    # pylint: disable=too-few-public-methods
    """JSON Web Key."""
    type_field_name = 'kty'
    TYPES = {}


@JWK.register
class JWKES(JWK):  # pragma: no cover
    # pylint: disable=abstract-class-not-used
    """ES JWK.

    .. warning:: This is not yet implemented!

    """
    typ = 'ES'

    def fields_to_json(self):
        raise NotImplementedError()

    @classmethod
    def fields_from_json(cls, jobj):
        raise NotImplementedError()


@JWK.register
class JWKOct(JWK):
    """Symmetric JWK."""
    typ = 'oct'
    __slots__ = ('key',)

    def fields_to_json(self):
        # TODO: An "alg" member SHOULD also be present to identify the
        # algorithm intended to be used with the key, unless the
        # application uses another means or convention to determine
        # the algorithm used.
        return {'k': self.key}

    @classmethod
    def fields_from_json(cls, jobj):
        return cls(key=jobj['k'])


@JWK.register
class JWKRSA(JWK):
    """RSA JWK."""
    typ = 'RSA'
    __slots__ = ('key',)

    @classmethod
    def _encode_param(cls, data):
        def _leading_zeros(arg):
            if len(arg) % 2:
                return '0' + arg
            return arg

        return b64.b64encode(binascii.unhexlify(
            _leading_zeros(hex(data)[2:].rstrip('L'))))

    @classmethod
    def _decode_param(cls, data):
        try:
            return long(binascii.hexlify(json_util.decode_b64jose(data)), 16)
        except ValueError:  # invalid literal for long() with base 16
            raise errors.DeserializationError()

    @classmethod
    def load(cls, key):
        """Load RSA key from string.

        :param str key: RSA key in string form.

        :returns:
        :rtype: :class:`JWKRSA`

        """
        return cls(key=Crypto.PublicKey.RSA.importKey(key))

    @classmethod
    def fields_from_json(cls, jobj):
        return cls(key=Crypto.PublicKey.RSA.construct(
            (cls._decode_param(jobj['n']),
             cls._decode_param(jobj['e']))))

    def fields_to_json(self):
        return {
            'n': self._encode_param(self.key.n),
            'e': self._encode_param(self.key.e),
        }

