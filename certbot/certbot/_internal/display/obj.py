"""This modules define the actual display implementations used in Certbot"""
import logging
import sys
from typing import Optional
from typing import Union

import zope.component
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot._internal import constants
from certbot._internal.display import completer
from certbot._internal.display import util
from certbot.compat import os

logger = logging.getLogger(__name__)

# Display exit codes
OK = "ok"
"""Display exit code indicating user acceptance."""

CANCEL = "cancel"
"""Display exit code for a user canceling the display."""

# Display constants
SIDE_FRAME = ("- " * 39) + "-"
"""Display boundary (alternates spaces, so when copy-pasted, markdown doesn't interpret
it as a heading)"""

# This class holds the global state of the display service. Using this class
# eliminates potential gotchas that exist if self.display was just a global
# variable. In particular, in functions `_DISPLAY = <value>` would create a
# local variable unless the programmer remembered to use the `global` keyword.
# Adding a level of indirection causes the lookup of the global _DisplayService
# object to happen first avoiding this potential bug.
class _DisplayService:
    def __init__(self):
        self.display: Optional[Union[FileDisplay, NoninteractiveDisplay]] = None


_SERVICE = _DisplayService()


# This use of IDisplay can be removed when this class is no longer accessible
# through the public API in certbot.display.util.
@zope.interface.implementer(interfaces.IDisplay)
class FileDisplay:
    """File-based display."""
    # see https://github.com/certbot/certbot/issues/3915

    def __init__(self, outfile, force_interactive):
        super().__init__()
        self.outfile = outfile
        self.force_interactive = force_interactive
        self.skipped_interaction = False

    def notification(self, message, pause=True,
                     wrap=True, force_interactive=False,
                     decorate=True):
        """Displays a notification and waits for user acceptance.

        :param str message: Message to display
        :param bool pause: Whether or not the program should pause for the
            user's confirmation
        :param bool wrap: Whether or not the application should wrap text
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions
        :param bool decorate: Whether to surround the message with a
            decorated frame

        """
        if wrap:
            message = util.wrap_lines(message)

        logger.debug("Notifying user: %s", message)

        self.outfile.write(
            (("{line}{frame}{line}" if decorate else "") +
             "{msg}{line}" +
             ("{frame}{line}" if decorate else ""))
                .format(line=os.linesep, frame=SIDE_FRAME, msg=message)
        )
        self.outfile.flush()

        if pause:
            if self._can_interact(force_interactive):
                util.input_with_timeout("Press Enter to Continue")
            else:
                logger.debug("Not pausing for user confirmation")

    def menu(self, message, choices, ok_label=None, cancel_label=None,  # pylint: disable=unused-argument
             help_label=None, default=None,  # pylint: disable=unused-argument
             cli_flag=None, force_interactive=False, **unused_kwargs):
        """Display a menu.

        .. todo:: This doesn't enable the help label/button (I wasn't sold on
           any interface I came up with for this). It would be a nice feature

        :param str message: title of menu
        :param choices: Menu lines, len must be > 0
        :type choices: list of tuples (tag, item) or
            list of descriptions (tags will be enumerated)
        :param default: default value to return (if one exists)
        :param str cli_flag: option used to set this value with the CLI
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of (`code`, `index`) where
            `code` - str display exit code
            `index` - int index of the user's selection

        :rtype: tuple

        """
        if self._return_default(message, default, cli_flag, force_interactive):
            return OK, default

        self._print_menu(message, choices)

        code, selection = self._get_valid_int_ans(len(choices))

        return code, selection - 1

    def input(self, message, default=None,
              cli_flag=None, force_interactive=False, **unused_kwargs):
        """Accept input from the user.

        :param str message: message to display to the user
        :param default: default value to return (if one exists)
        :param str cli_flag: option used to set this value with the CLI
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of (`code`, `input`) where
            `code` - str display exit code
            `input` - str of the user's input
        :rtype: tuple

        """
        if self._return_default(message, default, cli_flag, force_interactive):
            return OK, default

        # Trailing space must be added outside of util.wrap_lines to
        # be preserved
        message = util.wrap_lines("%s (Enter 'c' to cancel):" % message) + " "
        ans = util.input_with_timeout(message)

        if ans in ("c", "C"):
            return CANCEL, "-1"
        return OK, ans

    def yesno(self, message, yes_label="Yes", no_label="No", default=None,
              cli_flag=None, force_interactive=False, **unused_kwargs):
        """Query the user with a yes/no question.

        Yes and No label must begin with different letters, and must contain at
        least one letter each.

        :param str message: question for the user
        :param str yes_label: Label of the "Yes" parameter
        :param str no_label: Label of the "No" parameter
        :param default: default value to return (if one exists)
        :param str cli_flag: option used to set this value with the CLI
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: True for "Yes", False for "No"
        :rtype: bool

        """
        if self._return_default(message, default, cli_flag, force_interactive):
            return default

        message = util.wrap_lines(message)

        self.outfile.write("{0}{frame}{msg}{0}{frame}".format(
            os.linesep, frame=SIDE_FRAME + os.linesep, msg=message))
        self.outfile.flush()

        while True:
            ans = util.input_with_timeout("{yes}/{no}: ".format(
                yes=util.parens_around_char(yes_label),
                no=util.parens_around_char(no_label)))

            # Couldn't get pylint indentation right with elif
            # elif doesn't matter in this situation
            if (ans.startswith(yes_label[0].lower()) or
                ans.startswith(yes_label[0].upper())):
                return True
            if (ans.startswith(no_label[0].lower()) or
                ans.startswith(no_label[0].upper())):
                return False

    def checklist(self, message, tags, default=None,
                  cli_flag=None, force_interactive=False, **unused_kwargs):
        """Display a checklist.

        :param str message: Message to display to user
        :param list tags: `str` tags to select, len(tags) > 0
        :param default: default value to return (if one exists)
        :param str cli_flag: option used to set this value with the CLI
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of (`code`, `tags`) where
            `code` - str display exit code
            `tags` - list of selected tags
        :rtype: tuple

        """
        if self._return_default(message, default, cli_flag, force_interactive):
            return OK, default

        while True:
            self._print_menu(message, tags)

            code, ans = self.input("Select the appropriate numbers separated "
                                   "by commas and/or spaces, or leave input "
                                   "blank to select all options shown",
                                   force_interactive=True)

            if code == OK:
                if not ans.strip():
                    ans = " ".join(str(x) for x in range(1, len(tags)+1))
                indices = util.separate_list_input(ans)
                selected_tags = self._scrub_checklist_input(indices, tags)
                if selected_tags:
                    return code, selected_tags
                self.outfile.write(
                    "** Error - Invalid selection **%s" % os.linesep)
                self.outfile.flush()
            else:
                return code, []

    def _return_default(self, prompt, default, cli_flag, force_interactive):
        """Should we return the default instead of prompting the user?

        :param str prompt: prompt for the user
        :param default: default answer to prompt
        :param str cli_flag: command line option for setting an answer
            to this question
        :param bool force_interactive: if interactivity is forced

        :returns: True if we should return the default without prompting
        :rtype: bool

        """
        # assert_valid_call(prompt, default, cli_flag, force_interactive)
        if self._can_interact(force_interactive):
            return False
        if default is None:
            msg = "Unable to get an answer for the question:\n{0}".format(prompt)
            if cli_flag:
                msg += (
                    "\nYou can provide an answer on the "
                    "command line with the {0} flag.".format(cli_flag))
            raise errors.Error(msg)
        logger.debug(
            "Falling back to default %s for the prompt:\n%s",
            default, prompt)
        return True

    def _can_interact(self, force_interactive):
        """Can we safely interact with the user?

        :param bool force_interactive: if interactivity is forced

        :returns: True if the display can interact with the user
        :rtype: bool

        """
        if (self.force_interactive or force_interactive or
            sys.stdin.isatty() and self.outfile.isatty()):
            return True
        if not self.skipped_interaction:
            logger.warning(
                "Skipped user interaction because Certbot doesn't appear to "
                "be running in a terminal. You should probably include "
                "--non-interactive or %s on the command line.",
                constants.FORCE_INTERACTIVE_FLAG)
            self.skipped_interaction = True
        return False

    def directory_select(self, message, default=None, cli_flag=None,
                         force_interactive=False, **unused_kwargs):
        """Display a directory selection screen.

        :param str message: prompt to give the user
        :param default: default value to return (if one exists)
        :param str cli_flag: option used to set this value with the CLI
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of the form (`code`, `string`) where
            `code` - display exit code
            `string` - input entered by the user

        """
        with completer.Completer():
            return self.input(message, default, cli_flag, force_interactive)

    def _scrub_checklist_input(self, indices, tags):
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
        self.outfile.write(SIDE_FRAME + os.linesep)

        # Write out the menu choices
        for i, desc in enumerate(choices, 1):
            msg = "{num}: {desc}".format(num=i, desc=desc)
            self.outfile.write(util.wrap_lines(msg))

            # Keep this outside of the textwrap
            self.outfile.write(os.linesep)

        self.outfile.write(SIDE_FRAME + os.linesep)
        self.outfile.flush()

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
            ans = util.input_with_timeout(input_msg)
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
                self.outfile.flush()

        return OK, selection


# This use of IDisplay can be removed when this class is no longer accessible
# through the public API in certbot.display.util.
@zope.interface.implementer(interfaces.IDisplay)
class NoninteractiveDisplay:
    """A display utility implementation that never asks for interactive user input"""

    def __init__(self, outfile, *unused_args, **unused_kwargs):
        super().__init__()
        self.outfile = outfile

    def _interaction_fail(self, message, cli_flag, extra=""):
        """Error out in case of an attempt to interact in noninteractive mode"""
        msg = "Missing command line flag or config entry for this setting:\n"
        msg += message
        if extra:
            msg += "\n" + extra
        if cli_flag:
            msg += "\n\n(You can set this with the {0} flag)".format(cli_flag)
        raise errors.MissingCommandlineFlag(msg)

    def notification(self, message, pause=False, wrap=True, decorate=True, **unused_kwargs):  # pylint: disable=unused-argument
        """Displays a notification without waiting for user acceptance.

        :param str message: Message to display to stdout
        :param bool pause: The NoninteractiveDisplay waits for no keyboard
        :param bool wrap: Whether or not the application should wrap text
        :param bool decorate: Whether to apply a decorated frame to the message

        """
        if wrap:
            message = util.wrap_lines(message)

        logger.debug("Notifying user: %s", message)

        self.outfile.write(
            (("{line}{frame}{line}" if decorate else "") +
             "{msg}{line}" +
             ("{frame}{line}" if decorate else ""))
                .format(line=os.linesep, frame=SIDE_FRAME, msg=message)
        )
        self.outfile.flush()

    def menu(self, message, choices, ok_label=None, cancel_label=None,
             help_label=None, default=None, cli_flag=None, **unused_kwargs):
        # pylint: disable=unused-argument
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

    def input(self, message, default=None, cli_flag=None, **unused_kwargs):
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
        return OK, default

    def yesno(self, message, yes_label=None, no_label=None,  # pylint: disable=unused-argument
              default=None, cli_flag=None, **unused_kwargs):
        """Decide Yes or No, without asking anybody

        :param str message: question for the user
        :param dict kwargs: absorbs yes_label, no_label

        :raises errors.MissingCommandlineFlag: if there was no default
        :returns: True for "Yes", False for "No"
        :rtype: bool

        """
        if default is None:
            self._interaction_fail(message, cli_flag)
        return default

    def checklist(self, message, tags, default=None,
                  cli_flag=None, **unused_kwargs):
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
            self._interaction_fail(message, cli_flag, "? ".join(tags) + "?")
        return OK, default

    def directory_select(self, message, default=None,
                         cli_flag=None, **unused_kwargs):
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


def get_display() -> Union[FileDisplay, NoninteractiveDisplay]:
    """Get the display utility.

    :return: the display utility
    :rtype: Union[FileDisplay, NoninteractiveDisplay]
    :raise: ValueError if the display utility is not configured yet.

    """
    if not _SERVICE.display:
        raise ValueError("This function was called too early in Certbot's execution "
                         "as the display utility hasn't been configured yet.")
    return _SERVICE.display


def set_display(display: Union[FileDisplay, NoninteractiveDisplay]) -> None:
    """Set the display service.

    :param Union[FileDisplay, NoninteractiveDisplay] display: the display service

    """
    # This call is done only for retro-compatibility purposes.
    # TODO: Remove this call once zope dependencies are removed from Certbot.
    zope.component.provideUtility(display, interfaces.IDisplay)

    _SERVICE.display = display
