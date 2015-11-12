"""JSON Web Algorithm.

https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40

"""
import abc
import collections
import logging

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import padding

from acme.jose import errors
from acme.jose import interfaces
from acme.jose import jwk


logger = logging.getLogger(__name__)


class JWA(interfaces.JSONDeSerializable):  # pylint: disable=abstract-method
    # pylint: disable=too-few-public-methods
    # for some reason disable=abstract-method has to be on the line
    # above...
    """JSON Web Algorithm."""


class JWASignature(JWA, collections.Hashable):
    """JSON Web Signature Algorithm."""
    SIGNATURES = {}

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        if not isinstance(other, JWASignature):
            return NotImplemented
        return self.name == other.name

    def __hash__(self):
        return hash((self.__class__, self.name))

    def __ne__(self, other):
        return not self == other

    @classmethod
    def register(cls, signature_cls):
        """Register class for JSON deserialization."""
        cls.SIGNATURES[signature_cls.name] = signature_cls
        return signature_cls

    def to_partial_json(self):
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

    def __init__(self, name, hash_):
        super(_JWAHS, self).__init__(name)
        self.hash = hash_()

    def sign(self, key, msg):
        signer = hmac.HMAC(key, self.hash, backend=default_backend())
        signer.update(msg)
        return signer.finalize()

    def verify(self, key, msg, sig):
        verifier = hmac.HMAC(key, self.hash, backend=default_backend())
        verifier.update(msg)
        try:
            verifier.verify(sig)
        except cryptography.exceptions.InvalidSignature as error:
            logger.debug(error, exc_info=True)
            return False
        else:
            return True


class _JWARSA(object):

    kty = jwk.JWKRSA
    padding = NotImplemented
    hash = NotImplemented

    def sign(self, key, msg):
        """Sign the ``msg`` using ``key``."""
        try:
            signer = key.signer(self.padding, self.hash)
        except AttributeError as error:
            logger.debug(error, exc_info=True)
            raise errors.Error("Public key cannot be used for signing")
        except ValueError as error:  # digest too large
            logger.debug(error, exc_info=True)
            raise errors.Error(str(error))
        signer.update(msg)
        try:
            return signer.finalize()
        except ValueError as error:
            logger.debug(error, exc_info=True)
            raise errors.Error(str(error))

    def verify(self, key, msg, sig):
        """Verify the ``msg` and ``sig`` using ``key``."""
        verifier = key.verifier(sig, self.padding, self.hash)
        verifier.update(msg)
        try:
            verifier.verify()
        except cryptography.exceptions.InvalidSignature as error:
            logger.debug(error, exc_info=True)
            return False
        else:
            return True


class _JWARS(_JWARSA, JWASignature):

    def __init__(self, name, hash_):
        super(_JWARS, self).__init__(name)
        self.padding = padding.PKCS1v15()
        self.hash = hash_()


class _JWAPS(_JWARSA, JWASignature):

    def __init__(self, name, hash_):
        super(_JWAPS, self).__init__(name)
        self.padding = padding.PSS(
            mgf=padding.MGF1(hash_()),
            salt_length=padding.PSS.MAX_LENGTH)
        self.hash = hash_()


class _JWAES(JWASignature):  # pylint: disable=abstract-class-not-used

    # TODO: implement ES signatures

    def sign(self, key, msg):  # pragma: no cover
        raise NotImplementedError()

    def verify(self, key, msg, sig):  # pragma: no cover
        raise NotImplementedError()


HS256 = JWASignature.register(_JWAHS('HS256', hashes.SHA256))
HS384 = JWASignature.register(_JWAHS('HS384', hashes.SHA384))
HS512 = JWASignature.register(_JWAHS('HS512', hashes.SHA512))

RS256 = JWASignature.register(_JWARS('RS256', hashes.SHA256))
RS384 = JWASignature.register(_JWARS('RS384', hashes.SHA384))
RS512 = JWASignature.register(_JWARS('RS512', hashes.SHA512))

PS256 = JWASignature.register(_JWAPS('PS256', hashes.SHA256))
PS384 = JWASignature.register(_JWAPS('PS384', hashes.SHA384))
PS512 = JWASignature.register(_JWAPS('PS512', hashes.SHA512))

ES256 = JWASignature.register(_JWAES('ES256'))
ES384 = JWASignature.register(_JWAES('ES384'))
ES512 = JWASignature.register(_JWAES('ES512'))
