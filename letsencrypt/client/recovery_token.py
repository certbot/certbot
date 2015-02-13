"""Recovery Token Identifier Validation Challenge."""
import errno
import os

import zope.component

from letsencrypt.acme import challenges

from letsencrypt.client import le_util
from letsencrypt.client import interfaces


class RecoveryToken(object):
    """Recovery Token Identifier Validation Challenge.

    Based on draft-barnes-acme, section 6.4.

    """
    def __init__(self, server, direc):
        self.token_dir = os.path.join(direc, server)

    def perform(self, chall):
        """Perform the Recovery Token Challenge.

        :param chall: Recovery Token Challenge
        :type chall: :class:`letsencrypt.client.achallenges.RecoveryToken`

        :returns: response
        :rtype: dict

        """
        token_fp = os.path.join(self.token_dir, chall.domain)
        if os.path.isfile(token_fp):
            with open(token_fp) as token_fd:
                return challenges.RecoveryTokenResponse(token=token_fd.read())

        cancel, token = zope.component.getUtility(
            interfaces.IDisplay).input(
                "%s - Input Recovery Token: " % chall.domain)
        if cancel != 1:
            return challenges.RecoveryTokenResponse(token=token)

        return None

    def cleanup(self, chall):
        """Cleanup the saved recovery token if it exists.

        :param chall: Recovery Token Challenge
        :type chall: :class:`letsencrypt.client.achallenges.RecoveryToken`

        """
        try:
            le_util.safely_remove(os.path.join(self.token_dir, chall.domain))
        except OSError as err:
            if err.errno != errno.ENOENT:
                raise

    def requires_human(self, domain):
        """Indicates whether or not domain can be auto solved."""
        return not os.path.isfile(os.path.join(self.token_dir, domain))

    def store_token(self, domain, token):
        """Store token for later automatic use.

        :param str domain: domain associated with the token
        :param str token: token from authorization

        """
        le_util.make_or_verify_dir(self.token_dir, 0o700, os.geteuid())

        with open(os.path.join(self.token_dir, domain), "w") as token_fd:
            token_fd.write(str(token))
