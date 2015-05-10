"""JSON Web Key."""
import abc
import binascii

import Crypto.PublicKey.RSA

from letsencrypt.acme.jose import b64
from letsencrypt.acme.jose import errors
from letsencrypt.acme.jose import json_util
from letsencrypt.acme.jose import util


class JWK(json_util.TypedJSONObjectWithFields):
    # pylint: disable=too-few-public-methods
    """JSON Web Key."""
    type_field_name = 'kty'
    TYPES = {}

    @util.abstractclassmethod
    def load(cls, string):  # pragma: no cover
        """Load key from normalized string form."""
        raise NotImplementedError()

    @abc.abstractmethod
    def public(self):  # pragma: no cover
        """Generate JWK with public key.

        For symmetric cryptosystems, this would return ``self``.

        """
        # TODO: rename publickey to stay consistent with
        # HashableRSAKey.publickey
        raise NotImplementedError()


@JWK.register
class JWKES(JWK):  # pragma: no cover
    # pylint: disable=abstract-class-not-used
    """ES JWK.

    .. warning:: This is not yet implemented!

    """
    typ = 'ES'

    def fields_to_partial_json(self):
        raise NotImplementedError()

    @classmethod
    def fields_from_json(cls, jobj):
        raise NotImplementedError()

    @classmethod
    def load(cls, string):
        raise NotImplementedError()

    def public(self):
        raise NotImplementedError()


@JWK.register
class JWKOct(JWK):
    """Symmetric JWK."""
    typ = 'oct'
    __slots__ = ('key',)

    def fields_to_partial_json(self):
        # TODO: An "alg" member SHOULD also be present to identify the
        # algorithm intended to be used with the key, unless the
        # application uses another means or convention to determine
        # the algorithm used.
        return {'k': self.key}

    @classmethod
    def fields_from_json(cls, jobj):
        return cls(key=jobj['k'])

    @classmethod
    def load(cls, string):
        return cls(key=string)

    def public(self):
        return self


@JWK.register
class JWKRSA(JWK):
    """RSA JWK.

    :ivar key: `Crypto.PublicKey.RSA` wrapped in `.HashableRSAKey`

    """
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
    def load(cls, string):
        """Load RSA key from string.

        :param str string: RSA key in string form.

        :returns:
        :rtype: :class:`JWKRSA`

        """
        return cls(key=util.HashableRSAKey(
            Crypto.PublicKey.RSA.importKey(string)))

    def public(self):
        return type(self)(key=self.key.publickey())

    @classmethod
    def fields_from_json(cls, jobj):
        return cls(key=util.HashableRSAKey(
            Crypto.PublicKey.RSA.construct(
                (cls._decode_param(jobj['n']),
                 cls._decode_param(jobj['e'])))))

    def fields_to_partial_json(self):
        return {
            'n': self._encode_param(self.key.n),
            'e': self._encode_param(self.key.e),
        }
