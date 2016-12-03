"""Certbot display."""
import os
import textwrap

import six
import zope.interface

from certbot import interfaces
from certbot import errors
from certbot.display import completer


WIDTH = 72

# Display exit codes
OK = "ok"
"""Display exit code indicating user acceptance."""

CANCEL = "cancel"
"""Display exit code for a user canceling the display."""

HELP = "help"
"""Display exit code when for when the user requests more help."""

ESC = "esc"
"""Display exit code when the user hits Escape"""


def _wrap_lines(msg):
    """Format lines nicely to 80 chars.

    :param str msg: Original message

    :returns: Formatted message respecting newlines in message
    :rtype: str

    """
    lines = msg.splitlines()
    fixed_l = []

    for line in lines:
        fixed_l.append(textwrap.fill(
            line,
            80,
            break_long_words=False,
            break_on_hyphens=False))

    return os.linesep.join(fixed_l)

@zope.interface.implementer(interfaces.IDisplay)
class FileDisplay(object):
    """File-based display."""

    def __init__(self, outfile):
        super(FileDisplay, self).__init__()
        self.outfile = outfile

    def notification(self, message, pause=True, wrap=True):
        # pylint: disable=unused-argument
        """Displays a notification and waits for user acceptance.

        :param str message: Message to display
        :param bool pause: Whether or not the program should pause for the
            user's confirmation
        :param bool wrap: Whether or not the application should wrap text

        """
        side_frame = "-" * 79
        if wrap:
            message = _wrap_lines(message)
        self.outfile.write(
            "{line}{frame}{line}{msg}{line}{frame}{line}".format(
                line=os.linesep, frame=side_frame, msg=message))
        if pause:
            six.moves.input("Press Enter to Continue")

    def menu(self, message, choices, ok_label="", cancel_label="",
             help_label="", **unused_kwargs):
        # pylint: disable=unused-argument
        """Display a menu.

        .. todo:: This doesn't enable the help label/button (I wasn't sold on
           any interface I came up with for this). It would be a nice feature

        :param str message: title of menu
        :param choices: Menu lines, len must be > 0
        :type choices: list of tuples (tag, item) or
            list of descriptions (tags will be enumerated)
        :param dict _kwargs: absorbs default / cli_args

        :returns: tuple of (`code`, `index`) where
            `code` - str display exit code
            `index` - int index of the user's selection

        :rtype: tuple

        """
        self._print_menu(message, choices)

        code, selection = self._get_valid_int_ans(len(choices))

        return code, selection - 1

    def input(self, message, **unused_kwargs):
        # pylint: disable=no-self-use
        """Accept input from the user.

        :param str message: message to display to the user
        :param dict _kwargs: absorbs default / cli_args

        :returns: tuple of (`code`, `input`) where
            `code` - str display exit code
            `input` - str of the user's input
        :rtype: tuple

        """
        ans = six.moves.input(
            textwrap.fill(
                "%s (Enter 'c' to cancel): " % message,
                80,
                break_long_words=False,
                break_on_hyphens=False))

        if ans == "c" or ans == "C":
            return CANCEL, "-1"
        else:
            return OK, ans

    def yesno(self, message, yes_label="Yes", no_label="No", **unused_kwargs):
        """Query the user with a yes/no question.

        Yes and No label must begin with different letters, and must contain at
        least one letter each.

        :param str message: question for the user
        :param str yes_label: Label of the "Yes" parameter
        :param str no_label: Label of the "No" parameter
        :param dict _kwargs: absorbs default / cli_args

        :returns: True for "Yes", False for "No"
        :rtype: bool

        """
        side_frame = ("-" * 79) + os.linesep

        message = _wrap_lines(message)

        self.outfile.write("{0}{frame}{msg}{0}{frame}".format(
            os.linesep, frame=side_frame, msg=message))

        while True:
            ans = six.moves.input("{yes}/{no}: ".format(
                yes=_parens_around_char(yes_label),
                no=_parens_around_char(no_label)))

            # Couldn't get pylint indentation right with elif
            # elif doesn't matter in this situation
            if (ans.startswith(yes_label[0].lower()) or
                    ans.startswith(yes_label[0].upper())):
                return True
            if (ans.startswith(no_label[0].lower()) or
                    ans.startswith(no_label[0].upper())):
                return False

    def checklist(self, message, tags, default_status=True, **unused_kwargs):
        # pylint: disable=unused-argument
        """Display a checklist.

        :param str message: Message to display to user
        :param list tags: `str` tags to select, len(tags) > 0
        :param bool default_status: Not used for FileDisplay
        :param dict _kwargs: absorbs default / cli_args

        :returns: tuple of (`code`, `tags`) where
            `code` - str display exit code
            `tags` - list of selected tags
        :rtype: tuple

        """
        while True:
            self._print_menu(message, tags)

            code, ans = self.input("Select the appropriate numbers separated "
                                   "by commas and/or spaces, or leave input "
                                   "blank to select all options shown")

            if code == OK:
                if len(ans.strip()) == 0:
                    ans = " ".join(str(x) for x in range(1, len(tags)+1))
                indices = separate_list_input(ans)
                selected_tags = self._scrub_checklist_input(indices, tags)
                if selected_tags:
                    return code, selected_tags
                else:
                    self.outfile.write(
                        "** Error - Invalid selection **%s" % os.linesep)
            else:
                return code, []

    def directory_select(self, message, **unused_kwargs):
        """Display a directory selection screen.

        :param str message: prompt to give the user

        :returns: tuple of the form (`code`, `string`) where
            `code` - display exit code
            `string` - input entered by the user

        """
        with completer.Completer():
            return self.input(message)

    def _scrub_checklist_input(self, indices, tags):
        # pylint: disable=no-self-use
        """Validate input and transform indices to appropriate tags.

        :param list indices: input
        :param list tags: Original tags of the checklist

        :returns: valid tags the user selected
        :rtype: :class:`list` of :class:`str`

        """
        # They should all be of type int
        try:
            indices = [int(index) for index in indices]
        except ValueError:
            return []

        # Remove duplicates
        indices = list(set(indices))

        # Check all input is within range
        for index in indices:
            if index < 1 or index > len(tags):
                return []
        # Transform indices to appropriate tags
        return [tags[index - 1] for index in indices]

    def _print_menu(self, message, choices):
        """Print a menu on the screen.

        :param str message: title of menu
        :param choices: Menu lines
        :type choices: list of tuples (tag, item) or
            list of descriptions (tags will be enumerated)

        """
        # Can take either tuples or single items in choices list
        if choices and isinstance(choices[0], tuple):
            choices = ["%s - %s" % (c[0], c[1]) for c in choices]

        # Write out the message to the user
        self.outfile.write(
            "{new}{msg}{new}".format(new=os.linesep, msg=message))
        side_frame = ("-" * 79) + os.linesep
        self.outfile.write(side_frame)

        # Write out the menu choices
        for i, desc in enumerate(choices, 1):
            self.outfile.write(
                textwrap.fill(
                    "{num}: {desc}".format(num=i, desc=desc),
                    80,
                    break_long_words=False,
                    break_on_hyphens=False))

            # Keep this outside of the textwrap
            self.outfile.write(os.linesep)

        self.outfile.write(side_frame)

    def _get_valid_int_ans(self, max_):
        """Get a numerical selection.

        :param int max: The maximum entry (len of choices), must be positive

        :returns: tuple of the form (`code`, `selection`) where
            `code` - str display exit code ('ok' or cancel')
            `selection` - int user's selection
        :rtype: tuple

        """
        selection = -1
        if max_ > 1:
            input_msg = ("Select the appropriate number "
                         "[1-{max_}] then [enter] (press 'c' to "
                         "cancel): ".format(max_=max_))
        else:
            input_msg = ("Press 1 [enter] to confirm the selection "
                         "(press 'c' to cancel): ")
        while selection < 1:
            ans = six.moves.input(input_msg)
            if ans.startswith("c") or ans.startswith("C"):
                return CANCEL, -1
            try:
                selection = int(ans)
                if selection < 1 or selection > max_:
                    selection = -1
                    raise ValueError

            except ValueError:
                self.outfile.write(
                    "{0}** Invalid input **{0}".format(os.linesep))

        return OK, selection


@zope.interface.implementer(interfaces.IDisplay)
class NoninteractiveDisplay(object):
    """An iDisplay implementation that never asks for interactive user input"""

    def __init__(self, outfile):
        super(NoninteractiveDisplay, self).__init__()
        self.outfile = outfile

    def _interaction_fail(self, message, cli_flag, extra=""):
        "Error out in case of an attempt to interact in noninteractive mode"
        msg = "Missing command line flag or config entry for this setting:\n"
        msg += message
        if extra:
            msg += "\n" + extra
        if cli_flag:
            msg += "\n\n(You can set this with the {0} flag)".format(cli_flag)
        raise errors.MissingCommandlineFlag(msg)

    def notification(self, message, pause=False, wrap=True):
        # pylint: disable=unused-argument
        """Displays a notification without waiting for user acceptance.

        :param str message: Message to display to stdout
        :param bool pause: The NoninteractiveDisplay waits for no keyboard
        :param bool wrap: Whether or not the application should wrap text

        """
        side_frame = "-" * 79
        if wrap:
            message = _wrap_lines(message)
        self.outfile.write(
            "{line}{frame}{line}{msg}{line}{frame}{line}".format(
                line=os.linesep, frame=side_frame, msg=message))

    def menu(self, message, choices, ok_label=None, cancel_label=None,
             help_label=None, default=None, cli_flag=None):
        # pylint: disable=unused-argument,too-many-arguments
        """Avoid displaying a menu.

        :param str message: title of menu
        :param choices: Menu lines, len must be > 0
        :type choices: list of tuples (tag, item) or
            list of descriptions (tags will be enumerated)
        :param int default: the default choice
        :param dict kwargs: absorbs various irrelevant labelling arguments

        :returns: tuple of (`code`, `index`) where
            `code` - str display exit code
            `index` - int index of the user's selection
        :rtype: tuple
        :raises errors.MissingCommandlineFlag: if there was no default

        """
        if default is None:
            self._interaction_fail(message, cli_flag, "Choices: " + repr(choices))

        return OK, default

    def input(self, message, default=None, cli_flag=None):
        """Accept input from the user.

        :param str message: message to display to the user

        :returns: tuple of (`code`, `input`) where
            `code` - str display exit code
            `input` - str of the user's input
        :rtype: tuple
        :raises errors.MissingCommandlineFlag: if there was no default

        """
        if default is None:
            self._interaction_fail(message, cli_flag)
        else:
            return OK, default

    def yesno(self, message, yes_label=None, no_label=None, default=None, cli_flag=None):
        # pylint: disable=unused-argument
        """Decide Yes or No, without asking anybody

        :param str message: question for the user
        :param dict kwargs: absorbs yes_label, no_label

        :raises errors.MissingCommandlineFlag: if there was no default
        :returns: True for "Yes", False for "No"
        :rtype: bool

        """
        if default is None:
            self._interaction_fail(message, cli_flag)
        else:
            return default

    def checklist(self, message, tags, default=None, cli_flag=None, **kwargs):
        # pylint: disable=unused-argument
        """Display a checklist.

        :param str message: Message to display to user
        :param list tags: `str` tags to select, len(tags) > 0
        :param dict kwargs: absorbs default_status arg

        :returns: tuple of (`code`, `tags`) where
            `code` - str display exit code
            `tags` - list of selected tags
        :rtype: tuple

        """
        if default is None:
            self._interaction_fail(message, cli_flag, "? ".join(tags))
        else:
            return OK, default

    def directory_select(self, message, default=None, cli_flag=None):
        """Simulate prompting the user for a directory.

        This function returns default if it is not ``None``, otherwise,
        an exception is raised explaining the problem. If cli_flag is
        not ``None``, the error message will include the flag that can
        be used to set this value with the CLI.

        :param str message: prompt to give the user
        :param default: default value to return (if one exists)
        :param str cli_flag: option used to set this value with the CLI

        :returns: tuple of the form (`code`, `string`) where
            `code` - int display exit code
            `string` - input entered by the user

        """
        return self.input(message, default, cli_flag)


def separate_list_input(input_):
    """Separate a comma or space separated list.

    :param str input_: input from the user

    :returns: strings
    :rtype: list

    """
    no_commas = input_.replace(",", " ")
    # Each string is naturally unicode, this causes problems with M2Crypto SANs
    # TODO: check if above is still true when M2Crypto is gone ^
    return [str(string) for string in no_commas.split()]


def _parens_around_char(label):
    """Place parens around first character of label.

    :param str label: Must contain at least one character

    """
    return "({first}){rest}".format(first=label[0], rest=label[1:])
