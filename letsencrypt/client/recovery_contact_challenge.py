"""Recovery Contact Identifier Validation Challenge.

.. note:: This class is not complete and is not included in the project
    currently.

"""
import time

import dialog
import requests
import zope.interface

from letsencrypt.client import interfaces


class RecoveryContact(object):
    """Recovery Contact Identifier Validation Challenge.

    Based on draft-barnes-acme, section 6.3.

    """
    zope.interface.implements(interfaces.IChallenge)

    def __init__(self, activation_url="", success_url="", contact="",
                 poll_delay=3):
        super(RecoveryContact, self).__init__()
        self.token = ""
        self.activation_url = activation_url
        self.success_url = success_url
        self.contact = contact
        self.poll_delay = poll_delay

    def perform(self, quiet=True):  # pylint: disable=missing-docstring
        d = dialog.Dialog()  # pylint: disable=invalid-name
        if quiet:
            if self.success_url:
                d.infobox(self.get_display_string())
                return self.poll(10, quiet)
            else:
                code, self.token = d.inputbox(self.get_display_string())
                if code != d.OK:
                    return False

        else:
            print self.get_display_string()
            if self.success_url:
                return self.poll(10, quiet)
            else:
                self.token = raw_input("Enter the recovery token:")

        return True

    def cleanup(self):  # pylint: disable=no-self-use,missing-docstring
        return

    def get_display_string(self):
        """Create information message for the user.

        :returns: Message to be displayed to the user.
        :rtype: str

        """
        msg = "Recovery Contact Challenge: "
        if self.activation_url:
            msg += "Proceed to the URL to continue " + self.activation_url

        if self.activation_url and self.contact:
            msg += " or respond to the recovery email sent to " + self.contact
        elif self.contact:
            msg += "Recovery email sent to" + self.contact

        return msg

    def poll(self, rounds=10, quiet=True):
        """Poll the server.

        :param int rounds: Number of poll attempts.
        :param bool quiet: Display dialog box if True, raw prompt otherwise.

        :returns:
        :rtype: bool

        """
        for _ in xrange(rounds):
            if requests.get(self.success_url).status_code != 200:
                time.sleep(self.poll_delay)
            else:
                return True
        if self.prompt_continue(quiet):
            return self.poll(rounds, quiet)
        else:
            return False

    def prompt_continue(self, quiet=True):  # pylint: disable=no-self-use
        """Prompt user for continuation.

        :param bool quiet: Display dialog box if True, raw prompt otherwise.

        :returns: True if user agreed, False otherwise.
        :rtype: bool

        """
        prompt = ("You have not completed the challenge yet, "
                  "would you like to continue?")
        if quiet:
            ans = dialog.Dialog().yesno(prompt, width=70)
        else:
            ans = raw_input(prompt + "y/n")

        return ans.startswith('y') or ans.startswith('Y')

    def generate_response(self):  # pylint: disable=missing-docstring
        if not self.token:
            return {"type": "recoveryContact"}
        return {
            "type": "recoveryContact",
            "token": self.token,
        }
