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
from typing import Any
import warnings

import josepy as jose

from acme import challenges, messages
from acme.challenges import Challenge

logger = logging.getLogger(__name__)


class AnnotatedChallenge(jose.ImmutableMap):
    """Client annotated challenge.

    Wraps around server provided challenge and annotates with data
    useful for the client.

    :ivar ~.challb: Wrapped `~.ChallengeBody`.

    """
    __slots__ = ('challb',)
    _acme_type: type[Challenge] = NotImplemented

    def __getattr__(self, name: str) -> Any:
        return getattr(self.challb, name)

    def __getattribute__(self, name: str) -> Any:
        if name == 'domain':
            warnings.warn("the domain attribute is deprecated and will be removed in "
                        "an upcoming release", DeprecationWarning)
        return object.__getattribute__(self, name)

    def __hash__(self) -> int:
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', 'domain attribute is deprecated')
            return super().__hash__()

    def __init__(self, **kwargs: Any) -> None: # pylint: disable=super-init-not-called
        if 'identifier' not in kwargs:
            kwargs['identifier'] = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=kwargs['domain'])
        if 'domain' not in kwargs:
            kwargs['domain'] = kwargs['identifier'].value
        super().__init__(**kwargs)


class KeyAuthorizationAnnotatedChallenge(AnnotatedChallenge):
    """Client annotated `KeyAuthorizationChallenge` challenge."""
    __slots__ = ('challb', 'domain', 'account_key', 'identifier') # pylint: disable=redefined-slots-in-subclass

    def response_and_validation(self, *args: Any, **kwargs: Any
        ) -> tuple['challenges.KeyAuthorizationChallengeResponse', Any]:
        """Generate response and validation."""
        return self.challb.chall.response_and_validation(
            self.account_key, *args, **kwargs)


class DNS(AnnotatedChallenge):
    """Client annotated "dns" ACME challenge."""
    __slots__ = ('challb', 'domain', 'identifier') # pylint: disable=redefined-slots-in-subclass
    acme_type = challenges.DNS

class Other(AnnotatedChallenge):
    """Client annotated ACME challenge of an unknown type."""
    __slots__ = ('challb', 'domain', 'identifier') # pylint: disable=redefined-slots-in-subclass
    acme_type = challenges.Challenge
