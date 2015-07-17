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
from acme import challenges
from acme import jose

from letsencrypt import crypto_util


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

    :ivar .Account account:

    """
    __slots__ = ('challb', 'domain', 'account')
    acme_type = challenges.DVSNI

    def gen_cert_and_response(self, key_pem=None, bits=2048, alg=jose.RS256):
        """Generate a DVSNI cert and save it to filepath.

        :param bytes key_pem: Private PEM-encoded key used for
            certificate generation. If none provided, a fresh key will
            be generated.
        :param int bits: Number of bits for fresh key generation.
        :param .JWAAlgorithm alg:

        :returns: ``(response, cert_pem, key_pem)`` tuple,  where
            ``response`` is an instance of
            `acme.challenges.DVSNIResponse`, ``cert_pem`` is the
            PEM-encoded certificate and ``key_pem`` is PEM-encoded
            private key.
        :rtype: tuple

        """
        key_pem = crypto_util.make_key(bits) if key_pem is None else key_pem
        response = challenges.DVSNIResponse(validation=jose.JWS.sign(
            payload=self.challb.chall.json_dumps().encode('utf-8'),
            alg=alg,
            key=self.account.key,
            include_jwk=False,
        ))
        cert_pem = crypto_util.make_ss_cert(
            key_pem, ["some CN", response.z_domain], force_san=True)
        return response, cert_pem, key_pem


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
