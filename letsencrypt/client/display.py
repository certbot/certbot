import textwrap

import dialog
import zope.interface

from letsencrypt.client import interfaces


WIDTH = 72
HEIGHT = 20


class NcursesDisplay(object):
    zope.interface.implements(interfaces.IDisplay)

    def __init__(self, width=WIDTH, height=HEIGHT):
        super(NcursesDisplay, self).__init__()
        self.dialog = dialog.Dialog()
        self.width = width
        self.height = height

    def generic_notification(self, message):
        self.dialog.msgbox(message, width=self.width)

    def generic_menu(self, message, choices, input_text=""):
        # Can accept either tuples or just the actual choices
        if choices and isinstance(choices[0], tuple):
            code, selection = self.dialog.menu(
                message, choices=choices, width=self.width, height=self.height)
            return code, str(selection)
        else:
            choices = list(enumerate(choices, 1))
            code, tag = self.dialog.menu(
                message, choices=choices, width=self.width, height=self.height)

            return code(int(tag) - 1)

    def generic_input(self, message):
        return self.dialog.inputbox(message)

    def generic_yesno(self, message, yes="Yes", no="No"):
        return self.dialog.DIALOG_OK == self.dialog.yesno(
            message, self.height, self.width, yes_label=yes, no_label=no)

    def filter_names(self, names):
        choices = [(n, "", 0) for n in names]
        code, names = self.dialog.checklist(
            "Which names would you like to activate HTTPS for?",
            choices=choices)
        return code, [str(s) for s in names]

    def success_installation(self, domains):
        self.dialog.msgbox(
            "\nCongratulations! You have successfully enabled "
            + gen_https_names(domains) + "!", width=self.width)

    def display_certs(self, certs):
        list_choices = [
            (str(i+1), "%s | %s | %s" %
             (str(c["cn"].ljust(self.width - 39)),
              c["not_before"].strftime("%m-%d-%y"),
              "Installed" if c["installed"] else ""))
            for i, c in enumerate(certs)]

        code, tag = self.dialog.menu(
            "Which certificates would you like to revoke?",
            choices=list_choices, help_button=True,
            help_label="More Info", ok_label="Revoke",
            width=self.width, height=self.height)
        if not tag:
            tag = -1
        return code, (int(tag) - 1)

    def confirm_revocation(self, cert):
        text = ("Are you sure you would like to revoke the following "
                "certificate:\n")
        text += cert_info_frame(cert)
        text += "This action cannot be reversed!"
        return self.dialog.DIALOG_OK == self.dialog.yesno(
            text, width=self.width, height=self.height)

    def more_info_cert(self, cert):
        text = "Certificate Information:\n"
        text += cert_info_frame(cert)
        print text
        self.dialog.msgbox(text, width=self.width, height=self.height)

    def redirect_by_default(self):
        choices = [
            ("Easy", "Allow both HTTP and HTTPS access to these sites"),
            ("Secure", "Make all requests redirect to secure HTTPS access")]

        result = self.generic_menu(
            "Please choose whether HTTPS access is required or optional.",
            choices, "Please enter the appropriate number")

        if result[0] != OK:
            return False

        # different answer for each type of display
        return str(result[1]) == "Secure" or result[1] == 1


class FileDisplay(object):
    zope.interface.implements(interfaces.IDisplay)

    def __init__(self, outfile):
        super(FileDisplay, self).__init__()
        self.outfile = outfile

    def generic_notification(self, message):
        side_frame = '-' * (79)
        wm = textwrap.fill(message, 80)
        text = "\n%s\n%s\n%s\n" % (side_frame, wm, side_frame)
        self.outfile.write(text)
        raw_input("Press Enter to Continue")

    def generic_menu(self, message, choices, input_text=""):
        # Can take either tuples or single items in choices list
        if choices and isinstance(choices[0], tuple):
            choices = ["%s - %s" % (c[0], c[1]) for c in choices]

        self.outfile.write("\n%s\n" % message)
        side_frame = '-' * (79)
        self.outfile.write("%s\n" % side_frame)

        for i, choice in enumerate(choices, 1):
            self.outfile.write(textwrap.fill(
                "%d: %s" % (i, choice), 80) + '\n')

        self.outfile.write("%s\n" % side_frame)

        code, selection = self.__get_valid_int_ans(
            "%s (c to cancel): " % input_text)

        return code, (selection - 1)

    def generic_input(self, message):
        ans = raw_input("%s (Enter c to cancel)\n" % message)

        if ans.startswith('c') or ans.startswith('C'):
            return CANCEL, -1
        else:
            return OK, ans

    def generic_yesno(self, message, yes_label="Yes", no_label="No"):
        self.outfile.write("\n%s\n" % textwrap.fill(message, 80))
        ans = raw_input("y/n: ")
        return ans.startswith('y') or ans.startswith('Y')

    def filter_names(self, names):
        code, tag = self.generic_menu(
            "Choose the names would you like to upgrade to HTTPS?",
            names, "Select the number of the name: ")

        # Make sure to return a list...
        return code, [names[tag]]

    def display_certs(self, certs):
        menu_choices = [(str(i+1), str(c["cn"]) + " - " + c["pub_key"] +
                         " - " + str(c["not_before"])[:-6])
                        for i, c in enumerate(certs)]

        self.outfile.write("Which certificate would you like to revoke?\n")
        for choice in menu_choices:
            self.outfile.write(textwrap.fill(
                "%s: %s - %s Signed (UTC): %s\n" % choice[:4]))

        return self.__get_valid_int_ans("Revoke Number (c to cancel): ") - 1

    def __get_valid_int_ans(self, input_string):
        valid_ans = False

        e_msg = "Please input a number or the letter c to cancel\n"
        while not valid_ans:

            ans = raw_input(input_string)
            if ans.startswith('c') or ans.startswith('C'):
                code = CANCEL
                selection = -1
                valid_ans = True
            else:
                try:
                    selection = int(ans)
                    # TODO add check to make sure it is liess than max
                    if selection < 0:
                        self.outfile.write(e_msg)
                        continue
                    code = OK
                    valid_ans = True
                except ValueError:
                    self.outfile.write(e_msg)

        return code, selection

    def success_installation(self, domains):
        s_f = '*' * (79)
        wm = textwrap.fill(("Congratulations! You have successfully " +
                            "enabled %s!") % gen_https_names(domains))
        msg = "%s\n%s\n%s\n"
        self.outfile.write(msg % (s_f, wm, s_f))

    def confirm_revocation(self, cert):
        self.outfile.write("Are you sure you would like to revoke "
                           "the following certificate:\n")
        self.outfile.write(cert_info_frame(cert))
        self.outfile("This action cannot be reversed!\n")
        ans = raw_input("y/n")
        return ans.startswith('y') or ans.startswith('Y')

    def more_info_cert(self, cert):
        self.outfile.write("\nCertificate Information:\n")
        self.outfile.write(cert_info_frame(cert))

OK = "ok"
CANCEL = "cancel"
HELP = "help"


def cert_info_frame(cert):
    text = "-" * (WIDTH - 4) + "\n"
    text += cert_info_string(cert)
    text += "-" * (WIDTH - 4)
    return text


def cert_info_string(cert):
    text = "Subject: %s\n" % cert["subject"]
    text += "SAN: %s\n" % cert["san"]
    text += "Issuer: %s\n" % cert["issuer"]
    text += "Public Key: %s\n" % cert["pub_key"]
    text += "Not Before: %s\n" % str(cert["not_before"])
    text += "Not After: %s\n" % str(cert["not_after"])
    text += "Serial Number: %s\n" % cert["serial"]
    text += "SHA1: %s\n" % cert["fingerprint"]
    text += "Installed: %s\n" % cert["installed"]
    return text


def gen_https_names(domains):
    """Returns a string of the https domains.

    Domains are formatted nicely with https:// prepended to each.
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
