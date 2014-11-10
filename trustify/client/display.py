import dialog
from trustify.client import logger

d = dialog.Dialog()

WIDTH = 70 
HEIGHT = 16


# TODO: This whole class really needs to be refactored into two classes - one for curses one for text

def success_installation(curses, domains):
    if curses:
        d.msgbox("\nCongratulations! You have successfully enabled " + gen_https_names(domains) + "!", width=WIDTH)
    else:
        logger.info("Congratulations! You have successfully enabled " + gen_https_names(domains) + "!")

def redirect_by_default(curses):
    if curses:
        choices = [("Easy", "Allow both HTTP and HTTPS access to these sites"), ("Secure", "Make all requests redirect to secure HTTPS access")]
        result = d.menu("Please choose whether HTTPS access is required or optional.", width=WIDTH, choices=choices)
        if result[0] != 0:
            return False
        return result[1] == "Secure"

    else:
        ans = raw_input("Would you like to redirect all normal HTTP traffic to HTTPS? y/n")
        return ans.startswith('y') or ans.startswith('Y')


def gen_https_names(domains):
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


def confirm_revocation(cert):
    text = "Are you sure you would like to revoke the following certificate:\n"
    text += cert_info_frame(cert)
    text += "This action cannot be reversed!"
    a = d.yesno(text, width=WIDTH, height=HEIGHT)
    return a == d.DIALOG_OK

def cert_info_frame(cert):
    text = "-" * (WIDTH - 4) + "\n"
    text += cert_info_string(cert)
    text += "-" * (WIDTH - 4)
    return text

def more_info_cert(cert):
    text = "Certificate Information:\n"
    text += cert_info_frame(cert)
    d.msgbox(text, width=WIDTH, height=HEIGHT)

def cert_info_string(cert):
    text = "Subject: %s\n" % cert["subject"]
    text += "SAN: %s\n" % cert["san"]
    text += "Issuer: %s\n" % cert["issuer"]
    text += "Public Key: %s\n" % cert["pub_key"]
    text += "Not Before: %s\n" % str(cert["not_before"])
    text += "Not After: %s\n" % str(cert["not_after"])
    text += "Serial Number: %s\n" % cert["serial"]
    text += "SHA1: %s\n" % cert["fingerprint"]
    return text
