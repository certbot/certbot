"""Other ACME objects."""
import functools
import logging

import Crypto.Random
import Crypto.PublicKey.RSA

from letsencrypt.acme import jose
from letsencrypt.acme.jose import json_util


class Signature(jose.JSONObjectWithFields):
    """ACME signature.

    :ivar str alg: Signature algorithm.
    :ivar str sig: Signature.
    :ivar str nonce: Nonce.

    :ivar jwk: JWK.
    :type jwk: :class:`JWK`

    """
    NONCE_SIZE = 16
    """Minimum size of nonce in bytes."""

    alg = json_util.Field('alg', decoder=jose.JWASignature.from_json)
    sig = json_util.Field('sig', encoder=jose.b64encode,
                          decoder=json_util.decode_b64jose)
    nonce = json_util.Field(
        'nonce', encoder=jose.b64encode, decoder=functools.partial(
            json_util.decode_b64jose, size=NONCE_SIZE, minimum=True))
    jwk = json_util.Field('jwk', decoder=jose.JWK.from_json)

    @classmethod
    def from_msg(cls, msg, key, nonce=None, nonce_size=None, alg=jose.RS256):
        """Create signature with nonce prepended to the message.

        .. todo:: Protect against crypto unicode errors... is this sufficient?
            Do I need to escape?

        :param str msg: Message to be signed.

        :param key: Key used for signing.
        :type key: :class:`Crypto.PublicKey.RSA`

        :param str nonce: Nonce to be used. If None, nonce of
            ``nonce_size`` will be randomly generated.
        :param int nonce_size: Size of the automatically generated nonce.
            Defaults to :const:`NONCE_SIZE`.

        """
        nonce_size = cls.NONCE_SIZE if nonce_size is None else nonce_size
        if nonce is None:
            nonce = Crypto.Random.get_random_bytes(nonce_size)

        msg_with_nonce = nonce + msg
        sig = alg.sign(key, nonce + msg)
        logging.debug('%s signed as %s', msg_with_nonce, sig)

        return cls(alg=alg, sig=sig, nonce=nonce,
                   jwk=alg.kty(key=key.publickey()))

    def verify(self, msg):
        """Verify the signature.

        :param str msg: Message that was used in signing.

        """
        # self.alg is not Field, but JWA | pylint: disable=no-member
        return self.alg.verify(self.jwk.key, self.nonce + msg, self.sig)
