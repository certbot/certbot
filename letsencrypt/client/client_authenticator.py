"""Client Authenticator"""
import zope.interface

from letsencrypt.client import challenge_util
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
    def __init__(self, server, config):
        """Initialize Client Authenticator.

        :param str server: ACME CA Server

        :param config: Configuration.
        :type config: :class:`letsencrypt.client.interfaces.IConfig`

        """
        self.rec_token = recovery_token.RecoveryToken(
            server, config.REV_TOKEN_DIRS)

    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Return list of challenge preferences."""
        return ["recoveryToken"]

    def perform(self, chall_list):
        """Perform client specific challenges for IAuthenticator"""
        responses = []
        for chall in chall_list:
            if isinstance(chall, challenge_util.RecTokenChall):
                responses.append(self.rec_token.perform(chall))
            else:
                raise errors.LetsEncryptClientAuthError("Unexpected Challenge")
        return responses

    def cleanup(self, chall_list):
        """Cleanup call for IAuthenticator."""
        for chall in chall_list:
            if isinstance(chall, challenge_util.RecTokenChall):
                self.rec_token.cleanup(chall)
            else:
                raise errors.LetsEncryptClientAuthError("Unexpected Challenge")
