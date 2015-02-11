"""Lets Encrypt display."""
import os
import textwrap

import dialog
import zope.interface

from letsencrypt.client import interfaces


WIDTH = 72
HEIGHT = 20


class CommonDisplayMixin(object):  # pylint: disable=too-few-public-methods
    """Mixin with methods common to classes implementing IDisplay."""

    def redirect_by_default(self):
        """Determines whether the user would like to redirect to HTTPS.

        :returns: True if redirect is desired, False otherwise
        :rtype: bool

        """
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


class NcursesDisplay(CommonDisplayMixin):
    """Ncurses-based display."""

    zope.interface.implements(interfaces.IDisplay)

    def __init__(self, width=WIDTH, height=HEIGHT):
        super(NcursesDisplay, self).__init__()
        self.dialog = dialog.Dialog()
        self.width = width
        self.height = height

    def generic_notification(self, message, height=10):
        """Display a notification to the user and wait for user acceptance.

        :param str message: Message to display
        :param int height: Height of the dialog box

        """
        self.dialog.msgbox(message, height, width=self.width)

    def generic_menu(self, message, choices, unused_input_text=""):
        """Display a menu.

        :param str message: title of menu
        :param choices: menu lines
        :type choices: list of tuples (tag, item) or
            list of items (tags will be enumerated)

        :returns: tuple of the form (code, tag) where
            code is a display exit code
            tag is the tag string corresponding to the item chosen
        :rtype: tuple

        """
        # Can accept either tuples or just the actual choices
        if choices and isinstance(choices[0], tuple):
            code, selection = self.dialog.menu(
                message, choices=choices, width=self.width, height=self.height)
            return code, str(selection)
        else:
            choices = list(enumerate(choices, 1))
            code, tag = self.dialog.menu(
                message, choices=choices, width=self.width, height=self.height)

            return code, int(tag) - 1

    def generic_input(self, message):
        """Display an input box to the user.

        :param str message: Message to display that asks for input.

        :returns: tuple of the form (code, string) where
            code is a display exit code
            string is the input entered by the user

        """
        return self.dialog.inputbox(message)

    def generic_yesno(self, message, yes_label="Yes", no_label="No"):
        """Display a Yes/No dialog box

        :param str message: message to display to user
        :param str yes_label: label on the 'yes' button
        :param str no_label: label on the 'no' button

        :returns: if yes_label was selected
        :rtype: bool

        """
        return self.dialog.DIALOG_OK == self.dialog.yesno(
            message, self.height, self.width,
            yes_label=yes_label, no_label=no_label)

    def filter_names(self, names):
        """Determine which names the user would like to select from a list.

        :param list names: domain names

        :returns: tuple of the form (code, names) where
            code is a display exit code
            names is a list of names selected
        :rtype: tuple

        """
        choices = [(n, "", 0) for n in names]
        code, names = self.dialog.checklist(
            "Which names would you like to activate HTTPS for?",
            choices=choices)
        return code, [str(s) for s in names]

    def success_installation(self, domains):
        """Display a box confirming the installation of HTTPS.

        :param list domains: domain names which were enabled

        """
        self.dialog.msgbox(
            "\nCongratulations! You have successfully enabled "
            + gen_https_names(domains) + "!", width=self.width)

    def display_certs(self, certs):
        """Display certificates for revocation.

        :param list certs: `list` of `dict` used throughout revoker.py

        :returns: tuple of the form (code, selection) where
            code is a display exit code
            selection is the user's int selection
        :rtype: tuple

        """
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
        """Confirm revocation screen.

        :param dict cert: cert dict used throughout revoker.py

        :returns: True if user would like to revoke, False otherwise
        :rtype: bool

        """
        text = ("Are you sure you would like to revoke the following "
                "certificate:\n")
        text += cert_info_frame(cert)
        text += "This action cannot be reversed!"
        return self.dialog.DIALOG_OK == self.dialog.yesno(
            text, width=self.width, height=self.height)

    def more_info_cert(self, cert):
        """Displays more information about the certificate.

        :param dict cert: cert dict used throughout revoker.py

        """
        text = "Certificate Information:\n"
        text += cert_info_frame(cert)
        self.dialog.msgbox(text, width=self.width, height=self.height)


class FileDisplay(CommonDisplayMixin):
    """File-based display."""

    zope.interface.implements(interfaces.IDisplay)

    def __init__(self, outfile):
        super(FileDisplay, self).__init__()
        self.outfile = outfile

    def generic_notification(self, message, unused_height):
        """Displays a notification and waits for user acceptance.

        :param str message: Message to display

        """
        side_frame = "-" * 79
        lines = message.splitlines()
        fixed_l = []
        for line in lines:
            fixed_l.append(textwrap.fill(line, 80))
        self.outfile.write(
            "{0}{1}{0}{2}{0}{1}{0}".format(
                os.linesep, side_frame, os.linesep.join(fixed_l)))
        raw_input("Press Enter to Continue")

    def generic_menu(self, message, choices, input_text=""):
        """Display a menu.

        :param str message: title of menu
        :param choices: Menu lines
        :type choices: list of tuples (tag, item) or
            list of items (tags will be enumerated)

        :returns: tuple of the form (code, tag) where
            code is a display exit code
            tag is the tag string corresponding to the item chosen
        :rtype: tuple

        """
        # Can take either tuples or single items in choices list
        if choices and isinstance(choices[0], tuple):
            choices = ["%s - %s" % (c[0], c[1]) for c in choices]

        self.outfile.write("\n%s\n" % message)
        side_frame = "-" * 79
        self.outfile.write("%s\n" % side_frame)

        for i, choice in enumerate(choices, 1):
            self.outfile.write(textwrap.fill(
                "%d: %s" % (i, choice), 80) + "\n")

        self.outfile.write("%s\n" % side_frame)

        code, selection = self._get_valid_int_ans(
            "%s (c to cancel): " % input_text)

        return code, (selection - 1)

    def generic_input(self, message):
        # pylint: disable=no-self-use
        """Accept input from the user

        :param str message: message to display to the user

        :returns: tuple of (code, input) where
            code is a display exit code
            input is a str of the user's input
        :rtype: tuple

        """
        ans = raw_input("%s (Enter c to cancel)\n" % message)

        if ans == "c" or ans == "C":
            return CANCEL, "-1"
        else:
            return OK, ans

    def generic_yesno(self, message, unused_yes_label="", unused_no_label=""):
        """Query the user with a yes/no question.

        :param str message: question for the user

        :returns: True for 'Yes', False for 'No"
        :rtype: bool

        """
        self.outfile.write("\n%s\n" % textwrap.fill(message, 80))
        ans = raw_input("y/n: ")
        return ans.startswith("y") or ans.startswith("Y")

    def filter_names(self, names):
        """Determine which names the user would like to select from a list.

        :param list names: domain names

        :returns: tuple of the form (code, names) where
            code is a display exit code
            names is a list of names selected
        :rtype: tuple

        """
        code, tag = self.generic_menu(
            "Choose the names would you like to upgrade to HTTPS?",
            names, "Select the number of the name: ")

        # Make sure to return a list...
        return code, [names[tag]]

    def success_installation(self, domains):
        """Display a box confirming the installation of HTTPS.

        :param list domains: domain names which were enabled

        """
        side_frame = "*" * 79
        msg = textwrap.fill("Congratulations! You have successfully "
                            "enabled %s!" % gen_https_names(domains))
        self.outfile.write("%s\n%s\n%s\n" % (side_frame, msg, side_frame))

    def display_certs(self, certs):
        """Display certificates for revocation.

        :param list certs: `list` of `dict` used throughout revoker.py

        :returns: tuple of the form (code, selection) where
            code is a display exit code
            selection is the user's int selection
        :rtype: tuple

        """
        menu_choices = [(str(i+1), str(c["cn"]) + " - " + c["pub_key"] +
                         " - " + str(c["not_before"])[:-6])
                        for i, c in enumerate(certs)]

        self.outfile.write("Which certificate would you like to revoke?\n")
        for choice in menu_choices:
            self.outfile.write(textwrap.fill(
                "%s: %s - %s Signed (UTC): %s\n" % choice[:4]))

        return self._get_valid_int_ans("Revoke Number (c to cancel): ") - 1

    def _get_valid_int_ans(self, input_string):
        """Get a numerical selection.

        :param str input_string: Instructions for the user to make a selection.

        :returns: tuple of the form (code, selection) where
            code is a display exit code
            selection is the user's int selection
        :rtype: tuple

        """
        valid_ans = False
        e_msg = "Please input a number or the letter c to cancel\n"
        while not valid_ans:

            ans = raw_input(input_string)
            if ans.startswith("c") or ans.startswith("C"):
                code = CANCEL
                selection = -1
                valid_ans = True
            else:
                try:
                    selection = int(ans)
                    # TODO add check to make sure it is less than max
                    if selection < 0:
                        self.outfile.write(e_msg)
                        continue
                    code = OK
                    valid_ans = True
                except ValueError:
                    self.outfile.write(e_msg)

        return code, selection

    def confirm_revocation(self, cert):
        """Confirm revocation screen.

        :param dict cert: cert dict used throughout revoker.py

        :returns: True if user would like to revoke, False otherwise
        :rtype: bool

        """
        self.outfile.write("Are you sure you would like to revoke "
                           "the following certificate:\n")
        self.outfile.write(cert_info_frame(cert))
        self.outfile("This action cannot be reversed!\n")
        ans = raw_input("y/n")
        return ans.startswith("y") or ans.startswith("Y")

    def more_info_cert(self, cert):
        """Displays more info about the cert.

        :param dict cert: cert dict used throughout revoker.py

        """
        self.outfile.write("\nCertificate Information:\n")
        self.outfile.write(cert_info_frame(cert))


# Display exit codes
OK = "ok"
"""Display exit code indicating user acceptance"""

CANCEL = "cancel"
"""Display exit code for a user canceling the display"""

HELP = "help"
"""Display exit code when for when the user requests more help."""


def cert_info_frame(cert):
    """Nicely frames a cert dict used in revoker.py"""
    text = "-" * (WIDTH - 4) + os.linesep
    text += cert_info_string(cert)
    text += "-" * (WIDTH - 4)
    return text


def cert_info_string(cert):
    """Turn a cert dict into a string."""
    text = []
    text.append("Subject: %s" % cert["subject"])
    text.append("SAN: %s" % cert["san"])
    text.append("Issuer: %s" % cert["issuer"])
    text.append("Public Key: %s" % cert["pub_key"])
    text.append("Not Before: %s" % str(cert["not_before"]))
    text.append("Not After: %s" % str(cert["not_after"]))
    text.append("Serial Number: %s" % cert["serial"])
    text.append("SHA1: %s" % cert["fingerprint"])
    text.append("Installed: %s" % cert["installed"])
    return os.linesep.join(text)


def gen_https_names(domains):
    """Returns a string of the https domains.

    Domains are formatted nicely with https:// prepended to each.

    :param list domains: Domains (:class:`str`)

    """
    return ", ".join("https://{0}".format(domain) for domain in domains)
