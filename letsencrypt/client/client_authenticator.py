"""Client Authenticator"""
import zope.interface

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import recovery_token


class ClientAuthenticator(object):
    """IAuthenticator for
    :const:`~letsencrypt.client.constants.CLIENT_CHALLENGES`.

    :ivar rec_token: Performs "recoveryToken" challenges
    :type rec_token: :class:`letsencrypt.client.recovery_token.RecoveryToken`

    """
    zope.interface.implements(interfaces.IAuthenticator)

    # This will have an installer soon for get_key/cert purposes
    def __init__(self, config):
        """Initialize Client Authenticator.

        :param config: Configuration.
        :type config: :class:`letsencrypt.client.interfaces.IConfig`

        """
        self.rec_token = recovery_token.RecoveryToken(
            config.server, config.rec_token_dir)

    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Return list of challenge preferences."""
        return [challenges.RecoveryToken]

    def perform(self, achalls):
        """Perform client specific challenges for IAuthenticator"""
        responses = []
        for achall in achalls:
            if isinstance(achall, achallenges.RecoveryToken):
                responses.append(self.rec_token.perform(achall))
            else:
                raise errors.LetsEncryptClientAuthError("Unexpected Challenge")
        return responses

    def cleanup(self, achalls):
        """Cleanup call for IAuthenticator."""
        for achall in achalls:
            if isinstance(achall, achallenges.RecoveryToken):
                self.rec_token.cleanup(achall)
            else:
                raise errors.LetsEncryptClientAuthError("Unexpected Challenge")
