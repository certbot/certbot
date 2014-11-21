import dialog
import requests
import time

from letsencrypt.client import challenge


class RecoveryContact(challenge.Challenge):

    def __init__(self, activationURL = "", successURL = "", contact = "", poll_delay = 3):
        self.token = ""
        self.activationURL = activationURL
        self.successURL = successURL
        self.contact = contact
        self.poll_delay = poll_delay

    def perform(self, quiet = True):
        d = dialog.Dialog()
        if quiet:
            if self.successURL:
                d.infobox(self.get_display_string())
                return self.poll(10, quiet)
            else:
                exit, self.token  = d.inputbox(self.get_display_string())
                if exit != d.OK:
                    return False

        else:
            print self.get_display_string()
            if successURL:
                return self.poll(10, quiet)
            else:
                self.token = raw_input("Enter the recovery token:")

        return True

    def cleanup(self):
        return

    def get_display_string(self):
        string = "Recovery Contact Challenge: "
        if self.activationURL:
            string += "Proceed to the URL to continue " + self.activationURL

        if self.activationURL and self.contact:
            string += " or respond to the recovery email sent to " + self.contact
        elif self.contact:
            string += "Recovery email sent to" + self.contact

    def poll(self, rounds = 10, quiet = True):
        for i in range(rounds):
            if requests.get(self.successURL).status_code != 200:
                time.sleep(self.poll_delay)
            else:
                return True
        if self.prompt_continue(quiet):
            return self.poll(rounds, quiet)
        else:
            return False
    def prompt_continue(self, quiet = True):
        prompt = "You have not completed the challenge yet, would you like to continue?"
        if quiet:
            ans = dialog.Dialog().yesno(prompt, width=70)
        else:
            ans = raw_input(prompt + "y/n")

        return ans.startswith('y') or ans.startswith('Y')


    def generate_response(self):
        if self.token == "":
            return {"type":"recoveryContact"}
        return {"type":"recoveryContact", "token":self.token}
