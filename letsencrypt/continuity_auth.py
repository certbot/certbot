"""Continuity Authenticator"""
import zope.interface

from acme import challenges

from letsencrypt import achallenges
from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt import proof_of_possession


class ContinuityAuthenticator(object):
    """IAuthenticator for
    :const:`~acme.challenges.ContinuityChallenge` class challenges.

    :ivar proof_of_pos: Performs "proofOfPossession" challenges.
    :type proof_of_pos:
        :class:`letsencrypt.proof_of_possession.Proof_of_Possession`

    """
    zope.interface.implements(interfaces.IAuthenticator)

    # This will have an installer soon for get_key/cert purposes
    def __init__(self, config, installer):  # pylint: disable=unused-argument
        """Initialize Client Authenticator.

        :param config: Configuration.
        :type config: :class:`letsencrypt.interfaces.IConfig`

        :param installer: Let's Encrypt Installer.
        :type installer: :class:`letsencrypt.interfaces.IInstaller`

        """
        self.proof_of_pos = proof_of_possession.ProofOfPossession(installer)

    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Return list of challenge preferences."""
        return [challenges.ProofOfPossession]

    def perform(self, achalls):
        """Perform client specific challenges for IAuthenticator"""
        responses = []
        for achall in achalls:
            if isinstance(achall, achallenges.ProofOfPossession):
                responses.append(self.proof_of_pos.perform(achall))
            else:
                raise errors.ContAuthError("Unexpected Challenge")
        return responses

    def cleanup(self, achalls):  # pylint: disable=no-self-use
        """Cleanup call for IAuthenticator."""
        for achall in achalls:
            if not isinstance(achall, achallenges.ProofOfPossession):
                raise errors.ContAuthError("Unexpected Challenge")
