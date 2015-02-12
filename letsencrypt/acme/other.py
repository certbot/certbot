"""Other ACME objects."""
import logging

from Crypto import Random
import Crypto.Hash.SHA256
import Crypto.Signature.PKCS1_v1_5

from letsencrypt.acme import jose
from letsencrypt.acme import util


class Signature(util.ACMEObject):
    """ACME signature.

    :ivar str alg: Signature algorithm.
    :ivar str sig: Signature.
    :ivar str nonce: Nonce.

    :ivar jwk: JWK.
    :type jwk: :class:`letsencrypt.acme.jose.JWK`

    .. todo:: Currently works for RSA keys only.

    """
    __slots__ = ('alg', 'sig', 'nonce', 'jwk')

    NONCE_LEN = 16
    """Size of nonce in bytes, as specified in the ACME protocol."""

    @classmethod
    def from_msg(cls, msg, key, nonce=None):
        """Create signature with nonce prepended to the message.

        .. todo:: Protect against crypto unicode errors... is this sufficient?
            Do I need to escape?

        :param str msg: Message to be signed.

        :param key: Key used for signing.
        :type key: :class:`Crypto.PublicKey.RSA`

        :param nonce: Nonce to be used. If None, nonce of
            :const:`NONCE_LEN` size will be randomly generated.
        :type nonce: str or None

        """
        if nonce is None:
            nonce = Random.get_random_bytes(cls.NONCE_LEN)

        msg_with_nonce = nonce + msg
        hashed = Crypto.Hash.SHA256.new(msg_with_nonce)
        sig = Crypto.Signature.PKCS1_v1_5.new(key).sign(hashed)

        logging.debug('%s signed as %s', msg_with_nonce, sig)

        return cls(alg='RS256', sig=sig, nonce=nonce,
                   jwk=jose.JWK(key=key.publickey()))

    def verify(self, msg):
        """Verify the signature.

        :param str msg: Message that was used in signing.

        """
        hashed = Crypto.Hash.SHA256.new(self.nonce + msg)
        return Crypto.Signature.PKCS1_v1_5.new(self.jwk.key).verify(
            hashed, self.sig)

    def to_json(self):
        return {
            'alg': self.alg,
            'sig': jose.b64encode(self.sig),
            'nonce': jose.b64encode(self.nonce),
            'jwk': self.jwk,
        }

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(alg=jobj['alg'], sig=jose.b64decode(jobj['sig']),
                   nonce=jose.b64decode(jobj['nonce']),
                   jwk=jose.JWK.from_valid_json(jobj['jwk']))
