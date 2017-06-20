"""Client annotated ACME challenges.

Please use names such as ``achall`` to distinguish from variables "of type"
:class:`acme.challenges.Challenge` (denoted by ``chall``)
and :class:`.ChallengeBody` (denoted by ``challb``)::

  from acme import challenges
  from acme import messages
  from certbot import achallenges

  chall = challenges.DNS(token='foo')
  challb = messages.ChallengeBody(chall=chall)
  achall = achallenges.DNS(chall=challb, domain='example.com')

Note, that all annotated challenges act as a proxy objects::

  achall.token == challb.token

"""
import logging
import six

from acme import challenges
from acme import jose

from certbot.compatibility import python_2_unicode_compatible

logger = logging.getLogger(__name__)


# pylint: disable=too-few-public-methods

@python_2_unicode_compatible
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

    def __str__(self):
        return self

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
