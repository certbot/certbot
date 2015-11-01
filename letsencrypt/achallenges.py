"""Client annotated ACME challenges.

Please use names such as ``achall`` to distiguish from variables "of type"
:class:`acme.challenges.Challenge` (denoted by ``chall``)
and :class:`.ChallengeBody` (denoted by ``challb``)::

  from acme import challenges
  from acme import messages
  from letsencrypt import achallenges

  chall = challenges.DNS(token='foo')
  challb = messages.ChallengeBody(chall=chall)
  achall = achallenges.DNS(chall=challb, domain='example.com')

Note, that all annotated challenges act as a proxy objects::

  achall.token == challb.token

"""
import logging

from acme import challenges
from acme import jose


logger = logging.getLogger(__name__)


# pylint: disable=too-few-public-methods


class AnnotatedChallenge(jose.ImmutableMap):
    """Client annotated challenge.

    Wraps around server provided challenge and annotates with data
    useful for the client.

    :ivar challb: Wrapped `~.ChallengeBody`.

    """
    __slots__ = ('challb',)
    acme_type = NotImplemented

    def __getattr__(self, name):
        return getattr(self.challb, name)


class DVSNI(AnnotatedChallenge):
    """Client annotated "dvsni" ACME challenge.

    :ivar .JWK account_key: Authorized Account Key

    """
    __slots__ = ('challb', 'domain', 'account_key')
    acme_type = challenges.DVSNI

    def gen_cert_and_response(self, key=None, bits=2048, alg=jose.RS256):
        """Generate a DVSNI cert and response.

        :param OpenSSL.crypto.PKey key: Private key used for
            certificate generation. If none provided, a fresh key will
            be generated.
        :param int bits: Number of bits for fresh key generation.
        :param .JWAAlgorithm alg:

        :returns: ``(response, cert_pem, key_pem)`` tuple,  where
            ``response`` is an instance of
            `acme.challenges.DVSNIResponse`, ``cert`` is a certificate
            (`OpenSSL.crypto.X509`) and ``key`` is a private key
            (`OpenSSL.crypto.PKey`).
        :rtype: tuple

        """
        response = self.challb.chall.gen_response(self.account_key, alg=alg)
        cert, key = response.gen_cert(key=key, bits=bits)
        return response, cert, key


class SimpleHTTP(AnnotatedChallenge):
    """Client annotated "simpleHttp" ACME challenge."""
    __slots__ = ('challb', 'domain', 'account_key')
    acme_type = challenges.SimpleHTTP

    def gen_response_and_validation(self, tls):
        """Generates a SimpleHTTP response and validation.

        :param bool tls: True if TLS should be used

        :returns: ``(response, validation)`` tuple, where ``response`` is
            an instance of `acme.challenges.SimpleHTTPResponse` and
            ``validation`` is an instance of
            `acme.challenges.SimpleHTTPProvisionedResource`.
        :rtype: tuple

        """
        response = challenges.SimpleHTTPResponse(tls=tls)

        validation = response.gen_validation(
            self.challb.chall, self.account_key)
        logger.debug("Simple HTTP validation payload: %s", validation.payload)
        return response, validation


class DNS(AnnotatedChallenge):
    """Client annotated "dns" ACME challenge."""
    __slots__ = ('challb', 'domain')
    acme_type = challenges.DNS


class RecoveryContact(AnnotatedChallenge):
    """Client annotated "recoveryContact" ACME challenge."""
    __slots__ = ('challb', 'domain')
    acme_type = challenges.RecoveryContact


class ProofOfPossession(AnnotatedChallenge):
    """Client annotated "proofOfPossession" ACME challenge."""
    __slots__ = ('challb', 'domain')
    acme_type = challenges.ProofOfPossession
