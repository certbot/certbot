import dialog
from trustify.client import logger



WIDTH = 70 
HEIGHT = 16

class SingletonD(object):
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SingletonD, cls).__new__(
                                cls, *args, **kwargs)
        return cls._instance


class Display(SingletonD):
    def success_installation(self, domains):
        raise Exception("Error no display defined")
    def redirect_by_default(self):
        raise Exception("Error no display defined")
    def gen_https_names(self, domains):
        """
        Returns a string of the domains formatted nicely with https:// prepended
        to each
        """
        result = ""
        if len(domains) > 2:
            for i in range(len(domains)-1):
                result = result + "https://" + domains[i] + ", "
            result = result + "and "
        if len(domains) == 2:
            return "https://" + domains[0] + " and https://" + domains[1]
        if domains:
            result = result + "https://" + domains[len(domains)-1]

        return result

    def confirm_revocation(self, cert):
        raise Exception("Error no display defined")


    def cert_info_frame(self, cert):
        text = "-" * (WIDTH - 4) + "\n"
        text += self.cert_info_string(cert)
        text += "-" * (WIDTH - 4)
        return text

    def cert_info_string(self, cert):
        text = "Subject: %s\n" % cert["subject"]
        text += "SAN: %s\n" % cert["san"]
        text += "Issuer: %s\n" % cert["issuer"]
        text += "Public Key: %s\n" % cert["pub_key"]
        text += "Not Before: %s\n" % str(cert["not_before"])
        text += "Not After: %s\n" % str(cert["not_after"])
        text += "Serial Number: %s\n" % cert["serial"]
        text += "SHA1: %s\n" % cert["fingerprint"]
        return text

    def more_info_cert(self, cert):
        raise Exception("Error no display defined")
        

import dialog
class NcursesDisplay(Display):

    def __init__(self):
        self.d = dialog.Dialog()

    def success_installation(self, domains):
        self.d.msgbox("\nCongratulations! You have successfully enabled " + self.gen_https_names(domains) + "!", width=WIDTH)
        

    def redirect_by_default(self):
        choices = [("Easy", "Allow both HTTP and HTTPS access to these sites"), ("Secure", "Make all requests redirect to secure HTTPS access")]
        result = self.d.menu("Please choose whether HTTPS access is required or optional.", width=WIDTH, choices=choices)
        if result[0] != 0:
            return False
        return result[1] == "Secure"    

    def confirm_revocation(self, cert):
        text = "Are you sure you would like to revoke the following certificate:\n"
        text += self.cert_info_frame(cert)
        text += "This action cannot be reversed!"
        a = self.d.yesno(text, width=WIDTH, height=HEIGHT)
        return a == self.d.DIALOG_OK

    def more_info_cert(self, cert):
        text = "Certificate Information:\n"
        text += self.cert_info_frame(cert)
        self.d.msgbox(text, width=WIDTH, height=HEIGHT)


class FileDisplay(Display):
    def __init__(self, outfile):
        self.outfile = outfile

    def success_installation(self, domains):
        outfile.write("Congratulations! You have successfully enabled " + self.gen_https_names(domains) + "!\n")

    def redirect_by_default(self):
        ans = raw_input("Would you like to redirect all normal HTTP traffic to HTTPS? y/n")
        return ans.startswith('y') or ans.startswith('Y')

    def confirm_revocation(self, cert):
        outfile.write("Are you sure you would like to revoke the following certificate:\n")
        outfile.write(self.cert_info_frame(cert))
        outfile("This action cannot be reversed!\n");
        ans = raw_input("y/n")
        return ans.startswith('y') or ans.startswith('Y')

    def more_info_cert(self, cert):
        outfile.write("\nCertificate Information:\n")
        outfile.write(self.cert_info_frame(cert))

display = None

def setDisplay(display_inst):
    global display
    display = display_inst


def cert_info_string(cert):
    return display.cert_info_string(cert)

def gen_https_names(domains):
    return display.gen_https_names(domains)

def success_installation(domains):
    return display.success_installation(domains)

def redirect_by_default():
    return display.redirect_by_default()

def confirm_revocation(cert):
    return display.confirm_revocation(cert)

def more_info_cert(cert):
    return display.more_info_cert(cert)
