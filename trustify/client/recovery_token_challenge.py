from trustify.client.challenge import Challenge
from trustify.client import logger
from trustify.client.CONFIG import RECOVERY_TOKEN_EXT
import dialog

class RecoveryToken(Challenge):
    
    def __init__(self):
        self.token = ""

    def perform(self, quiet = True):
        
        if quiet:
            cancel, self.token  = dialog.Dialog().inputbox("Please Input Recovery Token")
            if cancel == 1:
                return False
        else:
            self.token = raw_input("Enter the Recovery Token: ")
        
        return True

    def cleanup(self):
        pass

    def generate_response(self):
        return {"type":"recoveryToken", "token":self.token}
