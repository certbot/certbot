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
import OpenSSL

from acme import challenges
from acme.jose import util as jose_util

from letsencrypt import crypto_util


# pylint: disable=too-few-public-methods


class AnnotatedChallenge(jose_util.ImmutableMap):
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
    """Client annotated "dvsni" ACME challenge."""
    __slots__ = ('challb', 'domain', 'key')
    acme_type = challenges.DVSNI

    def gen_cert_and_response(self, s=None):  # pylint: disable=invalid-name
        """Generate a DVSNI cert and response.

        :returns: ``(cert_pem, response)`` tuple,  where ``cert_pem`` is the PEM
            encoded  certificate and ``response`` is an instance
            :class:`acme.challenges.DVSNIResponse`.
        :rtype: tuple

        """
        key = crypto_util.private_jwk_to_pyopenssl(self.key)
        response = challenges.DVSNIResponse(s=s)
        cert = response.gen_cert(self.challb.chall, self.domain, key)
        cert_pem = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)

        return cert_pem, response


class SimpleHTTP(AnnotatedChallenge):
    """Client annotated "simpleHttp" ACME challenge."""
    __slots__ = ('challb', 'domain', 'key')
    acme_type = challenges.SimpleHTTP


class DNS(AnnotatedChallenge):
    """Client annotated "dns" ACME challenge."""
    __slots__ = ('challb', 'domain')
    acme_type = challenges.DNS


class RecoveryContact(AnnotatedChallenge):
    """Client annotated "recoveryContact" ACME challenge."""
    __slots__ = ('challb', 'domain')
    acme_type = challenges.RecoveryContact


class RecoveryToken(AnnotatedChallenge):
    """Client annotated "recoveryToken" ACME challenge."""
    __slots__ = ('challb', 'domain')
    acme_type = challenges.RecoveryToken


class ProofOfPossession(AnnotatedChallenge):
    """Client annotated "proofOfPossession" ACME challenge."""
    __slots__ = ('challb', 'domain')
    acme_type = challenges.ProofOfPossession
