"""JSON objects in ACME protocol other than messages."""
import logging

from Crypto import Random
import Crypto.Hash.SHA256
import Crypto.Signature.PKCS1_v1_5

import zope.interface

from letsencrypt.acme import interfaces
from letsencrypt.acme import jose


class Signature(object):
    """ACME signature.

    :ivar str alg: Signature algorithm.
    :ivar str sig: Signature.
    :ivar str nonce: Nonce.

    :ivar jwk: JWK.
    :type jwk: :class:`letsencrypt.acme.jose.JWK`

    .. todo:: Currently works for RSA keys only.

    """
    zope.interface.implements(interfaces.IJSONSerializable)

    NONCE_LEN = 16
    """Size of nonce in bytes, as specified in the ACME protocol."""

    def __init__(self, alg, sig, nonce, jwk):
        self.alg = alg
        self.sig = sig
        self.nonce = nonce
        self.jwk = jwk

    @classmethod
    def from_msg(cls, msg, key, nonce=None):
        """Create signature with nonce prepended to the message.

        .. todo:: Change this over to M2Crypto... PKey

        .. todo:: Protect against crypto unicode errors... is this sufficient?
            Do I need to escape?

        :param str msg: Message to be signed.

        :param key: Key used for signing.
        :type key: :class:`Crypto.PublicKey.RSA`

        :param nonce: Nonce to be used. If None, nonce of
            :const:`NONCE_LEN` size will be randomly generated.
        :type nonce: str or None

        """
        msg = str(msg)  # TODO: ????
        if nonce is None:
            nonce = Random.get_random_bytes(cls.NONCE_LEN)

        msg_with_nonce = nonce + msg
        hashed = Crypto.Hash.SHA256.new(msg_with_nonce)
        sig = Crypto.Signature.PKCS1_v1_5.new(key).sign(hashed)

        logging.debug('%s signed as %s', msg_with_nonce, sig)

        return cls('RS256', sig, nonce, jose.JWK(key))

    def __eq__(self, other):
        if isinstance(other, Signature):
            return ((self.alg, self.sig, self.nonce, self.jwk) ==
                    (other.alg, other.sig, other.nonce, other.jwk))
        else:
            raise TypeError(
                'Unable to compare Signature object with: {0}'.format(other))

    def verify(self, msg):
        """Verify the signature.

        :param str msg: Message that was used in signing.

        """
        return self == self.from_msg(msg, self.jwk.key, self.nonce)

    def to_json(self):
        """Seriliaze to JSON."""
        return {
            'alg': self.alg,
            'sig': jose.b64encode(self.sig),
            'nonce': jose.b64encode(self.nonce),
            'jwk': self.jwk,
        }

    @classmethod
    def from_json(cls, jobj):
        """Deserialize from JSON."""
        return cls(jobj['alg'], jose.b64decode(jobj['sig']),
                   jose.b64decode(jobj['nonce']),
                   jose.JWK.from_json(jobj['jwk']))
