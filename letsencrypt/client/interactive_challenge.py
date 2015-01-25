"""Interactive challenge."""
import textwrap

import dialog
import zope.interface

from letsencrypt.client import interfaces


class InteractiveChallenge(object):
    """Interactive challenge.

    Interactive challenge displays the string sent by the CA formatted
    to fit on the screen of the client. The Challenge also adds proper
    instructions for how the client should continue the letsencrypt
    process.

    """
    zope.interface.implements(interfaces.IChallenge)

    BOX_SIZE = 70

    def __init__(self, string):
        super(InteractiveChallenge, self).__init__()
        self.string = string

    def perform(self, quiet=True):  # pylint: disable=missing-docstring
        if quiet:
            dialog.Dialog().msgbox(
                self.get_display_string(), width=self.BOX_SIZE)
        else:
            print self.get_display_string()
            raw_input('')

        return True

    def get_display_string(self):  # pylint: disable=missing-docstring
        return (textwrap.fill(self.string, width=self.BOX_SIZE) +
                "\n\nPlease Press Enter to Continue")

    # def formatted_reasons(self):
    #    return "\n\t* %s\n", self.reason
