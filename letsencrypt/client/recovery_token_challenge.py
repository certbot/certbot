"""Recovery Token Identifier Validation Challenge.

.. note:: This challenge has not been implemented into the project yet

"""
import zope.interface

from letsencrypt.client import display
from letsencrypt.client import interfaces


class RecoveryToken(object):
    """Recovery Token Identifier Validation Challenge.

    Based on draft-barnes-acme, section 6.4.

    """
    zope.interface.implements(interfaces.IChallenge)

    def __init__(self):
        super(RecoveryToken, self).__init__()
        self.token = ""

    def perform(self, quiet=True):
        cancel, self.token = display.generic_input(
            "Please Input Recovery Token: ")
        return cancel != 1

    def cleanup(self):
        pass

    def generate_response(self):
        return {
            "type": "recoveryToken",
            "token": self.token,
        }
