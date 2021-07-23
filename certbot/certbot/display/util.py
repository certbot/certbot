"""Certbot display.

This module (`certbot.display.util`) or its companion `certbot.display.ops`
should be used whenever:

- Displaying status information to the user on the terminal
- Collecting information from the user via prompts

Other messages can use the `logging` module. See `log.py`.

"""
import logging
import sys
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union


from certbot.compat import misc
# These imports are done to not break the public API of the module.
from certbot._internal.display.obj import FileDisplay  # pylint: disable=unused-import
from certbot._internal.display.obj import NoninteractiveDisplay  # pylint: disable=unused-import
from certbot._internal.display import obj

logger = logging.getLogger(__name__)

WIDTH = 72

# Display exit codes
OK = "ok"
"""Display exit code indicating user acceptance."""

CANCEL = "cancel"
"""Display exit code for a user canceling the display."""

HELP = "help"
"""Display exit code when for when the user requests more help. (UNUSED)"""

ESC = "esc"
"""Display exit code when the user hits Escape (UNUSED)"""

# Display constants
SIDE_FRAME = ("- " * 39) + "-"
"""Display boundary (alternates spaces, so when copy-pasted, markdown doesn't interpret
it as a heading)"""


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


def menu(message: str, choices: Union[List[str], Tuple[str, str]],
         default: Optional[int] = None, cli_flag: Optional[str] = None,
         force_interactive: bool = False) -> Tuple[str, int]:
    """Display a menu.

    .. todo:: This doesn't enable the help label/button (I wasn't sold on
        any interface I came up with for this). It would be a nice feature.

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
    return obj.get_display().menu(message, choices, default=default, cli_flag=cli_flag,
                                  force_interactive=force_interactive)


def input_text(message: str, default: Optional[str] = None, cli_flag: Optional[str] = None,
               force_interactive: bool = False) -> Tuple[str, str]:
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
    :param default: default value to return (if one exists)
    :param str cli_flag: option used to set this value with the CLI
    :param bool force_interactive: True if it's safe to prompt the user
        because it won't cause any workflow regressions

    :returns: True for "Yes", False for "No"
    :rtype: bool

    """
    return obj.get_display().yesno(message, yes_label=yes_label, no_label=no_label, default=default,
                                   cli_flag=cli_flag, force_interactive=force_interactive)


def checklist(message: str, tags: List[str], default: Optional[str] = None,
              cli_flag: Optional[str] = None,
              force_interactive: bool = False) -> Tuple[str, List[str]]:
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
    return obj.get_display().checklist(message, tags, default=default, cli_flag=cli_flag,
                                       force_interactive=force_interactive)


def directory_select(message: str, default: Optional[str] = None, cli_flag: Optional[str] = None,
                     force_interactive: bool = False) -> Tuple[int, str]:
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
    return obj.get_display().directory_select(message, default=default, cli_flag=cli_flag,
                                              force_interactive=force_interactive)


def input_with_timeout(prompt=None, timeout=36000.0):
    """Get user input with a timeout.

    Behaves the same as the builtin input, however, an error is raised if
    a user doesn't answer after timeout seconds. The default timeout
    value was chosen to place it just under 12 hours for users following
    our advice and running Certbot twice a day.

    :param str prompt: prompt to provide for input
    :param float timeout: maximum number of seconds to wait for input

    :returns: user response
    :rtype: str

    :raises errors.Error if no answer is given before the timeout

    """
    # use of sys.stdin and sys.stdout to mimic the builtin input based on
    # https://github.com/python/cpython/blob/baf7bb30a02aabde260143136bdf5b3738a1d409/Lib/getpass.py#L129
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()

    line = misc.readline_with_timeout(timeout, prompt)

    if not line:
        raise EOFError
    return line.rstrip('\n')


def assert_valid_call(prompt, default, cli_flag, force_interactive):
    """Verify that provided arguments is a valid IDisplay call.

    :param str prompt: prompt for the user
    :param default: default answer to prompt
    :param str cli_flag: command line option for setting an answer
        to this question
    :param bool force_interactive: if interactivity is forced by the
        IDisplay call

    """
    msg = "Invalid IDisplay call for this prompt:\n{0}".format(prompt)
    if cli_flag:
        msg += ("\nYou can set an answer to "
                "this prompt with the {0} flag".format(cli_flag))
    assert default is not None or force_interactive, msg


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


def summarize_domain_list(domains: List[str]) -> str:
    """Summarizes a list of domains in the format of:
        example.com.com and N more domains
    or if there is are only two domains:
        example.com and www.example.com
    or if there is only one domain:
        example.com

    :param list domains: `str` list of domains
    :returns: the domain list summary
    :rtype: str
    """
    if not domains:
        return ""

    l = len(domains)
    if l == 1:
        return domains[0]
    elif l == 2:
        return " and ".join(domains)
    else:
        return "{0} and {1} more domains".format(domains[0], l-1)
