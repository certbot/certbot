"""Lets Encrypt display."""
import os
import textwrap

import dialog
import zope.interface

from letsencrypt.client import interfaces


WIDTH = 72
HEIGHT = 20


class NcursesDisplay(object):
    """Ncurses-based display."""

    zope.interface.implements(interfaces.IDisplay)

    def __init__(self, width=WIDTH, height=HEIGHT):
        super(NcursesDisplay, self).__init__()
        self.dialog = dialog.Dialog()
        self.width = width
        self.height = height

    def notification(self, message, height=10):
        """Display a notification to the user and wait for user acceptance.

        :param str message: Message to display
        :param int height: Height of the dialog box

        """
        self.dialog.msgbox(message, height, width=self.width)

    def menu(self, message, choices, unused_input_text="",
                     ok_label="OK", help_label=""):
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
        if help_label:
            help_button = True
        else:
            help_button = False

        # Can accept either tuples or just the actual choices
        if choices and isinstance(choices[0], tuple):
            code, selection = self.dialog.menu(
                message, choices=choices, ok_label=ok_label,
                help_button=help_button, help_label=help_label,
                width=self.width, height=self.height)

            return code, str(selection)
        else:
            choices = list(enumerate(choices, 1))
            code, tag = self.dialog.menu(
                message, choices=choices, ok_label=ok_label,
                help_button=help_button, help_label=help_label,
                width=self.width, height=self.height)

            return code, int(tag) - 1

    def input(self, message):
        """Display an input box to the user.

        :param str message: Message to display that asks for input.

        :returns: tuple of the form (code, string) where
            code is a display exit code
            string is the input entered by the user

        """
        return self.dialog.inputbox(message)

    def yesno(self, message, yes_label="Yes", no_label="No"):
        """Display a Yes/No dialog box

        :param str message: message to display to user
        :param str yes_label: label on the "yes" button
        :param str no_label: label on the "no" button

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


class FileDisplay(object):
    """File-based display."""

    zope.interface.implements(interfaces.IDisplay)

    def __init__(self, outfile):
        super(FileDisplay, self).__init__()
        self.outfile = outfile

    def notification(self, message, unused_height):
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

    def menu(self, message, choices, input_text="",
                     unused_ok_label = "", unused_help_label=""):
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

    def input(self, message):
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

    def yesno(self, message, unused_yes_label="", unused_no_label=""):
        """Query the user with a yes/no question.

        :param str message: question for the user

        :returns: True for "Yes", False for "No"
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
        code, tag = self.menu(
            "Choose the names would you like to upgrade to HTTPS?",
            names, "Select the number of the name: ")

        # Make sure to return a list...
        return code, [names[tag]]

    def success_installation(self, domains):
        """Display a box confirming the installation of HTTPS.

        :param list domains: domain names which were enabled

        """
        side_frame = '*' * 79
        msg = textwrap.fill("Congratulations! You have successfully "
                            "enabled %s!" % gen_https_names(domains))
        self.outfile.write("%s\n%s\n%s\n" % (side_frame, msg, side_frame))


    def _get_valid_int_ans(self, input_string):
        """Get a numerical selection.

        :param str input_string: Instructions for the user to make a selection.

        :returns: tuple of the form (code, selection) where
            code is a display exit code
            selection is the user"s int selection
        :rtype: tuple

        """
        valid_ans = False
        e_msg = "Make a selection by inputting the appropriate number.\n"
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


# Display exit codes
OK = "ok"
"""Display exit code indicating user acceptance"""

CANCEL = "cancel"
"""Display exit code for a user canceling the display"""

HELP = "help"
"""Display exit code when for when the user requests more help."""


def gen_https_names(domains):
    """Returns a string of the https domains.

    Domains are formatted nicely with https:// prepended to each.
    .. todo:: This should not use +=, rewrite this with unittests

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
