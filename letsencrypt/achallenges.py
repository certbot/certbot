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


class KeyAuthorizationAnnotatedChallenge(AnnotatedChallenge):
    """Client annotated `KeyAuthorizationChallenge` challenge."""
    __slots__ = ('challb', 'domain', 'account_key')

    def response_and_validation(self, *args, **kwargs):
        """Generate response and validation."""
        return self.challb.chall.response_and_validation(
            self.account_key, *args, **kwargs)


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
