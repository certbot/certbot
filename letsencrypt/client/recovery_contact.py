"""Recovery Contact Identifier Validation Challenge."""
import urllib2

import zope.component

from letsencrypt.acme import challenges
from letsencrypt.client import display

class RecoveryContact(object):
    """Recovery Contact Identifier Validation Challenge.

    Based on draft-barnes-acme, section 6.3.

    """
    def perform(self, achall, delay=3, assume_failed_after=60):
        """Perform the Recovery Contact Challenge.

        :param achall: Recovery Contact Challenge
        :type achall: :class:`letsencrypt.client.achallenges.RecoveryContact`

        :returns: response
        :rtype: dict

        """
        try:
            activation_response = urllib2.urlopen(achall.activationURL)
        except urllib2.URLError:
            return False

        if activation_response.getcode() != 200:
            return False

        if achall.successURL:
            for _ in range(0, assume_failed_after / delay):
                logging.info("Waiting for %d seconds...", delay)
                time.sleep(delay)
                try:
                    success_response = urllib2.urlopen(achall.successURL)
                except urllib2.URLError:
                    pass
                if success_response.getcode() == 200:
                    return challenges.RecoveryContactResponse()
        else:
            code, token = zope.component.getUtility(
                interfaces.IDisplay).input(
                    "%s - Input Emailed Token: " % achall.domain)
            if code != display.CANCEL:
                return challenges.RecoveryContactResponse(token=token)

        return False
