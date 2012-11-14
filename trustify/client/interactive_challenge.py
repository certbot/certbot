from trustify.client.challenge import Challenge
from trustify.client import logger
import textwrap

############################################################
# Possible addition to challenge structure: priority parameter
# If only DVSNI and Payment are required, the user might want
# to be validated before submitting payment, allowing the user
# to gain confidence in the system.  If things do go poorly the 
# user has less invested in that particular session/transaction. 
#############################################################

###########################################################
# Interactive challlenge displays the string sent by the CA
# formatted to fit on the screen of the client
# The Challenge also adds proper instructions for how the
# client should continue the trustify process
###########################################################

class Interactive_Challenge(Challenge):
    BOX_SIZE = 70

    def __init__(self, string):
        self.string = string
        
    def perform(self, quiet=True):
        if quiet:
            dialog.Dialog().msgbox(get_display_string(), width=BOX_SIZE)
        else:
            print get_display_string()
            raw_input('')

        return True
    

    def get_display_string(self):
        return textwrap.fill(self.string, width=BOX_SIZE) + "\n\nPlease Press Enter to Continue"

    def formatted_reasons(self):
        return "\n\t* %s\n", self.reason
