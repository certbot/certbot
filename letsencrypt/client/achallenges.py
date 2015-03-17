"""Client annotated ACME challenges.

Please use names such as ``achall`` and ``ichall`` (respectively ``achalls``
and ``ichalls`` for collections) to distiguish from variables "of type"
:class:`letsencrypt.acme.challenges.Challenge` (denoted by ``chall``)::

  from letsencrypt.acme import challenges
  from letsencrypt.client import achallenges

  chall = challenges.DNS(token='foo')
  achall = achallenges.DNS(chall=chall, domain='example.com')
  ichall = achallenges.Indexed(achall=achall, index=0)

Note, that all annotated challenges act as a proxy objects::

  ichall.token == achall.token == chall.token

"""
from letsencrypt.acme import challenges
from letsencrypt.acme.jose import util as jose_util

from letsencrypt.client import crypto_util


# pylint: disable=too-few-public-methods


class AnnotatedChallenge(jose_util.ImmutableMap):
    """Client annotated challenge.

    Wraps around :class:`~letsencrypt.acme.challenges.Challenge` and
    annotates with data usfeul for the client.

    """
    acme_type = NotImplemented

    def __getattr__(self, name):
        return getattr(self.chall, name)


class DVSNI(AnnotatedChallenge):
    """Client annotated "dvsni" ACME challenge."""
    __slots__ = ('chall', 'domain', 'key')
    acme_type = challenges.DVSNI

    def gen_cert_and_response(self, s=None):  # pylint: disable=invalid-name
        """Generate a DVSNI cert and save it to filepath.

        :returns: ``(cert_pem, response)`` tuple,  where ``cert_pem`` is the PEM
            encoded  certificate and ``response`` is an instance
            :class:`letsencrypt.acme.challenges.DVSNIResponse`.
        :rtype: tuple

        """
        response = challenges.DVSNIResponse(s=s)
        cert_pem = crypto_util.make_ss_cert(self.key.pem, [
            self.nonce_domain, self.domain, response.z_domain(self.chall)])
        return cert_pem, response


class SimpleHTTPS(AnnotatedChallenge):
    """Client annotated "simpleHttps" ACME challenge."""
    __slots__ = ('chall', 'domain', 'key')
    acme_type = challenges.SimpleHTTPS


class DNS(AnnotatedChallenge):
    """Client annotated "dns" ACME challenge."""
    __slots__ = ('chall', 'domain')
    acme_type = challenges.DNS


class RecoveryContact(AnnotatedChallenge):
    """Client annotated "recoveryContact" ACME challenge."""
    __slots__ = ('chall', 'domain')
    acme_type = challenges.RecoveryContact


class RecoveryToken(AnnotatedChallenge):
    """Client annotated "recoveryToken" ACME challenge."""
    __slots__ = ('chall', 'domain')
    acme_type = challenges.RecoveryToken


class ProofOfPossession(AnnotatedChallenge):
    """Client annotated "proofOfPossession" ACME challenge."""
    __slots__ = ('chall', 'domain')
    acme_type = challenges.ProofOfPossession


class Indexed(jose_util.ImmutableMap):
    """Indexed and annotated ACME challenge.

    Wraps around :class:`AnnotatedChallenge` and annotates with an
    ``index`` in order to maintain  the proper position of the response
    within a larger challenge list.

    """
    __slots__ = ('achall', 'index')

    def __getattr__(self, name):
        return getattr(self.achall, name)
