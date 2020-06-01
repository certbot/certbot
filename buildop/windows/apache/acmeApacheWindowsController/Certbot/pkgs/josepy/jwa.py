"""JSON Web Algorithms.

https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40

"""
import abc
import logging

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.primitives import hmac  # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding  # type: ignore

from josepy import errors, interfaces, jwk

try:
    from collections.abc import Hashable  # pylint: disable=import-error
except ImportError:
    from collections import Hashable

logger = logging.getLogger(__name__)


class JWA(interfaces.JSONDeSerializable):  # pylint: disable=abstract-method
    # pylint: disable=too-few-public-methods
    # for some reason disable=abstract-method has to be on the line
    # above...
    """JSON Web Algorithm."""


class JWASignature(JWA, Hashable):  # type: ignore
    """Base class for JSON Web Signature Algorithms."""
    SIGNATURES = {}  # type: dict

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
        """Verify the ``msg`` and ``sig`` using ``key``."""
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
        # If cryptography library supports new style api (v1.4 and later)
        new_api = hasattr(key, "sign")
        try:
            if new_api:
                return key.sign(msg, self.padding, self.hash)
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
        # If cryptography library supports new style api (v1.4 and later)
        new_api = hasattr(key, "verify")
        if not new_api:
            verifier = key.verifier(sig, self.padding, self.hash)
            verifier.update(msg)
        try:
            if new_api:
                key.verify(sig, msg, self.padding, self.hash)
            else:
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


#: HMAC using SHA-256
HS256 = JWASignature.register(_JWAHS('HS256', hashes.SHA256))
#: HMAC using SHA-384
HS384 = JWASignature.register(_JWAHS('HS384', hashes.SHA384))
#: HMAC using SHA-512
HS512 = JWASignature.register(_JWAHS('HS512', hashes.SHA512))

#: RSASSA-PKCS-v1_5 using SHA-256
RS256 = JWASignature.register(_JWARS('RS256', hashes.SHA256))
#: RSASSA-PKCS-v1_5 using SHA-384
RS384 = JWASignature.register(_JWARS('RS384', hashes.SHA384))
#: RSASSA-PKCS-v1_5 using SHA-512
RS512 = JWASignature.register(_JWARS('RS512', hashes.SHA512))

#: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
PS256 = JWASignature.register(_JWAPS('PS256', hashes.SHA256))
#: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
PS384 = JWASignature.register(_JWAPS('PS384', hashes.SHA384))
#: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
PS512 = JWASignature.register(_JWAPS('PS512', hashes.SHA512))

#: ECDSA using P-256 and SHA-256
ES256 = JWASignature.register(_JWAES('ES256'))
#: ECDSA using P-384 and SHA-384
ES384 = JWASignature.register(_JWAES('ES384'))
#: ECDSA using P-521 and SHA-512
ES512 = JWASignature.register(_JWAES('ES512'))
