import textwrap

import dialog

from letsencrypt.client import challenge


###########################################################
# Interactive challenge displays the string sent by the CA
# formatted to fit on the screen of the client
# The Challenge also adds proper instructions for how the
# client should continue the letsencrypt process
###########################################################

class Interactive_Challenge(challenge.Challenge):
    BOX_SIZE = 70

    def __init__(self, string):
        self.string = string

    def perform(self, quiet=True):
        if quiet:
            dialog.Dialog().msgbox(self.get_display_string(), width=self.BOX_SIZE)
        else:
            print self.get_display_string()
            raw_input('')

        return True


    def get_display_string(self):
        return textwrap.fill(self.string, width=self.BOX_SIZE) + "\n\nPlease Press Enter to Continue"

    def formatted_reasons(self):
        return "\n\t* %s\n", self.reason
