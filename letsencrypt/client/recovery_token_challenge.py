"""Recovery Token Identifier Validation Challenge."""
import dialog

from letsencrypt.client import challenge


class RecoveryToken(challenge.Challenge):
    """Recovery Token Identifier Validation Challenge.

    Based on draft-barnes-acme, section 6.4.

    """

    def __init__(self, configurator):
        super(RecoveryToken, self).__init__(configurator)
        self.token = ""

    def perform(self, quiet=True):
        cancel, self.token = dialog.generic_input(
            "Please Input Recovery Token: ")
        return cancel != 1

    def cleanup(self):
        pass

    def generate_response(self):
        return {
            "type": "recoveryToken",
            "token": self.token,
        }
