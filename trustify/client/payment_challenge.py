from trustify.client.challenge import Challenge
from trustify.client import logger

# TODO: How is this determined?
curses = True;

############################################################
# Possible addition to challenge structure: priority parameter
# If only DVSNI and Payment are required, the user might want
# to be validated before submitting payment, allowing the user
# to gain confidence in the system.  If things do go poorly the 
# user has less invested in that particular session/transaction. 
#############################################################

class Payment_Challenge(Challenge):
    # Possible reasons: Wildcard Certificates, EV certificates
    # Malware scanning services, Organization or Identity validated certs
    def __init__(self, url, reason="Specialty Certificate"):
        self.url = url
    def perform(self, quiet=True):
        if curses:
            dialog.Dialog().msgbox("You are buying " + formatted_reasons() + " You will need to visit " + self.url + " to submit your payment\nPlease click continue once your payment has been submitted", width=70)
        return True
    
    def redo(self, quiet=True):
        """
        Some other message called when challenge verification wasn't successful
        This should probably be a standard challenge function for all failed
        challenge attempts
        """
        if curses:
            dialog.Dialog().msgbox("The CA did not record your payment, please visit " + self.url + " for more information or to finish processing your transaction.", width=70)

        return True
