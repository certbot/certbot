"""Other ACME objects."""
import binascii
import logging

import Crypto.Random
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_v1_5

from letsencrypt.acme import errors
from letsencrypt.acme import jose
from letsencrypt.acme import util


class JWK(util.ACMEObject):
    # pylint: disable=too-few-public-methods
    """JSON Web Key.

    .. todo:: Currently works for RSA public keys only.

    """
    __slots__ = ('key',)

    @classmethod
    def _encode_param(cls, data):
        def _leading_zeros(arg):
            if len(arg) % 2:
                return '0' + arg
            return arg

        return jose.b64encode(binascii.unhexlify(
            _leading_zeros(hex(data)[2:].rstrip('L'))))

    @classmethod
    def _decode_param(cls, data):
        try:
            return long(binascii.hexlify(cls._decode_b64jose(data)), 16)
        except ValueError:  # invalid literal for long() with base 16
            raise errors.ValidationError(data)

    def to_json(self):
        return {
            'kty': 'RSA',  # TODO
            'n': self._encode_param(self.key.n),
            'e': self._encode_param(self.key.e),
        }

    @classmethod
    def from_valid_json(cls, jobj):
        assert 'RSA' == jobj['kty']  # TODO
        return cls(key=Crypto.PublicKey.RSA.construct(
            (cls._decode_param(jobj['n']),
             cls._decode_param(jobj['e']))))


class Signature(util.ACMEObject):
    """ACME signature.

    :ivar str alg: Signature algorithm.
    :ivar str sig: Signature.
    :ivar str nonce: Nonce.

    :ivar jwk: JWK.
    :type jwk: :class:`JWK`

    .. todo:: Currently works for RSA keys only.

    """
    __slots__ = ('alg', 'sig', 'nonce', 'jwk')

    NONCE_SIZE = 16
    """Minimum size of nonce in bytes."""

    @classmethod
    def from_msg(cls, msg, key, nonce=None, nonce_size=None):
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
        hashed = Crypto.Hash.SHA256.new(msg_with_nonce)
        sig = Crypto.Signature.PKCS1_v1_5.new(key).sign(hashed)

        logging.debug('%s signed as %s', msg_with_nonce, sig)

        return cls(alg='RS256', sig=sig, nonce=nonce,
                   jwk=JWK(key=key.publickey()))

    def verify(self, msg):
        """Verify the signature.

        :param str msg: Message that was used in signing.

        """
        hashed = Crypto.Hash.SHA256.new(self.nonce + msg)
        return bool(Crypto.Signature.PKCS1_v1_5.new(self.jwk.key).verify(
            hashed, self.sig))

    def to_json(self):
        return {
            'alg': self.alg,
            'sig': jose.b64encode(self.sig),
            'nonce': jose.b64encode(self.nonce),
            'jwk': self.jwk,
        }

    @classmethod
    def from_valid_json(cls, jobj):
        assert jobj['alg'] == 'RS256'  # TODO: support other algorithms
        return cls(alg=jobj['alg'], sig=cls._decode_b64jose(jobj['sig']),
                   nonce=cls._decode_b64jose(
                       jobj['nonce'], cls.NONCE_SIZE, minimum=True),
                   jwk=JWK.from_valid_json(jobj['jwk']))
