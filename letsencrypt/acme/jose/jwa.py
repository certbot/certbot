"""JSON Web Algorithm.

https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40

"""
import abc

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512

from Crypto.Signature import PKCS1_PSS
from Crypto.Signature import PKCS1_v1_5

from letsencrypt.acme.jose import errors
from letsencrypt.acme.jose import interfaces
from letsencrypt.acme.jose import jwk


class JWA(interfaces.JSONDeSerializable):  # pylint: disable=abstract-method,too-few-public-methods
    """JSON Web Algorithm."""


class JWASignature(JWA):
    """JSON Web Signature Algorithm."""
    SIGNATURES = {}

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return isinstance(other, JWASignature) and self.name == other.name

    @classmethod
    def register(cls, signature_cls):
        """Register class for JSON deserialization."""
        cls.SIGNATURES[signature_cls.name] = signature_cls
        return signature_cls

    def to_json(self):
        return self.name

    @classmethod
    def from_json(cls, jobj):
        return cls.SIGNATURES[jobj]

    @abc.abstractmethod
    def sign(self, key, msg):  # pragma: no cover
        """Sign the ``msg`` using ``key``."""
        raise NotImplementedError()

    @abc.abstractmethod
    def verify(self, key, msg, sig):  # pragma: no cover
        """Verify the ``msg` and ``sig`` using ``key``."""
        raise NotImplementedError()

    def __repr__(self):
        return self.name


class _JWAHS(JWASignature):

    kty = jwk.JWKOct

    def __init__(self, name, digestmod):
        super(_JWAHS, self).__init__(name)
        self.digestmod = digestmod

    def sign(self, key, msg):
        return HMAC.new(key, msg, self.digestmod).digest()

    def verify(self, key, msg, sig):
        """Verify the signature.

        .. warning::
            Does not protect against timing attack (no constant compare).

        """
        return self.sign(key, msg) == sig


class _JWARS(JWASignature):

    kty = jwk.JWKRSA

    def __init__(self, name, padding, digestmod):
        super(_JWARS, self).__init__(name)
        self.padding = padding
        self.digestmod = digestmod

    def sign(self, key, msg):
        try:
            return self.padding.new(key).sign(self.digestmod.new(msg))
        except TypeError as error:  # key has no private part
            raise errors.Error(error)
        except (AttributeError, ValueError) as error:
            # key is too small: ValueError for PS, AttributeError for RS
            raise errors.Error(error)

    def verify(self, key, msg, sig):
        return self.padding.new(key).verify(self.digestmod.new(msg), sig)


class _JWAES(JWASignature):  # pylint: disable=abstract-class-not-used

    # TODO: implement ES signatures

    def sign(self, key, msg):  # pragma: no cover
        raise NotImplementedError()

    def verify(self, key, msg, sig): # pragma: no cover
        raise NotImplementedError()


HS256 = JWASignature.register(_JWAHS('HS256', SHA256))
HS384 = JWASignature.register(_JWAHS('HS384', SHA384))
HS512 = JWASignature.register(_JWAHS('HS512', SHA512))

RS256 = JWASignature.register(_JWARS('RS256', PKCS1_v1_5, SHA256))
RS384 = JWASignature.register(_JWARS('RS384', PKCS1_v1_5, SHA384))
RS512 = JWASignature.register(_JWARS('RS512', PKCS1_v1_5, SHA512))

PS256 = JWASignature.register(_JWARS('PS256', PKCS1_PSS, SHA256))
PS384 = JWASignature.register(_JWARS('PS384', PKCS1_PSS, SHA384))
PS512 = JWASignature.register(_JWARS('PS512', PKCS1_PSS, SHA512))

ES256 = JWASignature.register(_JWAES('ES256'))
ES256 = JWASignature.register(_JWAES('ES384'))
ES256 = JWASignature.register(_JWAES('ES512'))
