from letsencrypt.client.challenge import Challenge
from letsencrypt.client import logger
from letsencrypt.client.CONFIG import RECOVERY_TOKEN_EXT

class RecoveryToken(Challenge):
    
    def __init__(self):
        self.token = ""

    def perform(self, quiet = True):
        
        cancel, self.token  = dialog.generic_input("Please Input Recovery Token: ")
        if cancel == 1:
            return False
        
        return True

    def cleanup(self):
        pass

    def generate_response(self):
        return {"type":"recoveryToken", "token":self.token}
