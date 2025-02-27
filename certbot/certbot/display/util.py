"""Certbot display.

This module (`certbot.display.util`) or its companion `certbot.display.ops`
should be used whenever:

- Displaying status information to the user on the terminal
- Collecting information from the user via prompts

Other messages can use the `logging` module. See `log.py`.

"""

from typing import Optional
from typing import Union

from certbot._internal.display import obj

# These constants are defined this way to make them easier to document with
# Sphinx and to not couple our public docstrings to our internal ones.
OK = obj.OK
"""Display exit code indicating user acceptance."""

CANCEL = obj.CANCEL
"""Display exit code for a user canceling the display."""

WIDTH = 72

def notify(msg: str) -> None:
    """Display a basic status message.

    :param str msg: message to display

    """
    obj.get_display().notification(msg, pause=False, decorate=False, wrap=False)


def notification(message: str, pause: bool = True, wrap: bool = True,
                 force_interactive: bool = False, decorate: bool = True) -> None:
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
    obj.get_display().notification(message, pause=pause, wrap=wrap,
                                   force_interactive=force_interactive, decorate=decorate)


def menu(message: str, choices: Union[list[str], list[tuple[str, str]]],
         default: Optional[int] = None, cli_flag: Optional[str] = None,
         force_interactive: bool = False) -> tuple[str, int]:
    """Display a menu.

    .. todo:: This doesn't enable the help label/button (I wasn't sold on
        any interface I came up with for this). It would be a nice feature.

    :param str message: title of menu
    :param choices: Menu lines, len must be > 0
    :type choices: list of tuples (tag, item) or
        list of descriptions (tags will be enumerated)
    :param default: default value to return, if interaction is not possible
    :param str cli_flag: option used to set this value with the CLI
    :param bool force_interactive: True if it's safe to prompt the user
        because it won't cause any workflow regressions

    :returns: tuple of (`code`, `index`) where
        `code` - str display exit code
        `index` - int index of the user's selection

    :rtype: tuple

    """
    return obj.get_display().menu(message, choices, default=default, cli_flag=cli_flag,
                                  force_interactive=force_interactive)


def input_text(message: str, default: Optional[str] = None, cli_flag: Optional[str] = None,
               force_interactive: bool = False) -> tuple[str, str]:
    """Accept input from the user.

    :param str message: message to display to the user
    :param default: default value to return, if interaction is not possible
    :param str cli_flag: option used to set this value with the CLI
    :param bool force_interactive: True if it's safe to prompt the user
        because it won't cause any workflow regressions

    :returns: tuple of (`code`, `input`) where
        `code` - str display exit code
        `input` - str of the user's input
    :rtype: tuple

    """
    return obj.get_display().input(message, default=default, cli_flag=cli_flag,
                                   force_interactive=force_interactive)


def yesno(message: str, yes_label: str = "Yes", no_label: str = "No",
          default: Optional[bool] = None, cli_flag: Optional[str] = None,
          force_interactive: bool = False) -> bool:
    """Query the user with a yes/no question.

    Yes and No label must begin with different letters, and must contain at
    least one letter each.

    :param str message: question for the user
    :param str yes_label: Label of the "Yes" parameter
    :param str no_label: Label of the "No" parameter
    :param default: default value to return, if interaction is not possible
    :param str cli_flag: option used to set this value with the CLI
    :param bool force_interactive: True if it's safe to prompt the user
        because it won't cause any workflow regressions

    :returns: True for "Yes", False for "No"
    :rtype: bool

    """
    return obj.get_display().yesno(message, yes_label=yes_label, no_label=no_label, default=default,
                                   cli_flag=cli_flag, force_interactive=force_interactive)


def checklist(message: str, tags: list[str], default: Optional[list[str]] = None,
              cli_flag: Optional[str] = None,
              force_interactive: bool = False) -> tuple[str, list[str]]:
    """Display a checklist.

    :param str message: Message to display to user
    :param list tags: `str` tags to select, len(tags) > 0
    :param default: default value to return, if interaction is not possible
    :param str cli_flag: option used to set this value with the CLI
    :param bool force_interactive: True if it's safe to prompt the user
        because it won't cause any workflow regressions

    :returns: tuple of (`code`, `tags`) where
        `code` - str display exit code
        `tags` - list of selected tags
    :rtype: tuple

    """
    return obj.get_display().checklist(message, tags, default=default, cli_flag=cli_flag,
                                       force_interactive=force_interactive)


def directory_select(message: str, default: Optional[str] = None, cli_flag: Optional[str] = None,
                     force_interactive: bool = False) -> tuple[str, str]:
    """Display a directory selection screen.

    :param str message: prompt to give the user
    :param default: default value to return, if interaction is not possible
    :param str cli_flag: option used to set this value with the CLI
    :param bool force_interactive: True if it's safe to prompt the user
        because it won't cause any workflow regressions

    :returns: tuple of the form (`code`, `string`) where
        `code` - display exit code
        `string` - input entered by the user

    """
    return obj.get_display().directory_select(message, default=default, cli_flag=cli_flag,
                                              force_interactive=force_interactive)


def assert_valid_call(prompt: str, default: str, cli_flag: str, force_interactive: bool) -> None:
    """Verify that provided arguments is a valid display call.

    :param str prompt: prompt for the user
    :param default: default answer to prompt
    :param str cli_flag: command line option for setting an answer
        to this question
    :param bool force_interactive: if interactivity is forced

    """
    msg = "Invalid display call for this prompt:\n{0}".format(prompt)
    if cli_flag:
        msg += ("\nYou can set an answer to "
                "this prompt with the {0} flag".format(cli_flag))
    assert default is not None or force_interactive, msg
