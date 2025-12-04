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

from certbot import errors

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
            warnings.warn("The domain attribute is deprecated and will be removed in "
                        "an upcoming release. Access the AnnotatedChallenge.identifier.value "
                        "attribute instead",
                        DeprecationWarning)
        return super().__getattribute__(name)

    def __hash__(self) -> int:
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', 'the domain attribute is deprecated')
            return super().__hash__()

    def __eq__(self, other: Any) -> bool:
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', 'the domain attribute is deprecated')
            return super().__eq__(other)

    def __init__(self, **kwargs: Any) -> None:
        if 'domain' in kwargs:
            if 'identifier' in kwargs:
                raise errors.Error("AnnotatedChallenge takes either domain or identifier, not both")
            warnings.warn("The domain attribute is deprecated and will be removed in "
                          "an upcoming release. domain=<domain> with "
                          "identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, "
                          "value=<domain>)",
                          DeprecationWarning)
        if 'identifier' not in kwargs:
            kwargs['identifier'] = messages.Identifier(
                typ=messages.IDENTIFIER_FQDN, value=kwargs['domain'])
        if 'domain' not in kwargs:
            if kwargs['identifier'].typ == messages.IDENTIFIER_FQDN:
                kwargs['domain'] = kwargs['identifier'].value
            else:
                kwargs['domain'] = None
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
