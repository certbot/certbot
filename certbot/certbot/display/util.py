"""Certbot display.

This module (`certbot.display.util`) or its companion `certbot.display.ops`
should be used whenever:

- Displaying status information to the user on the terminal
- Collecting information from the user via prompts

Other messages can use the `logging` module. See `log.py`.

"""
import sys
from types import ModuleType
from typing import Any
from typing import cast
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union
import warnings

from certbot._internal.display import obj
# These specific imports from certbot._internal.display.obj and
# certbot._internal.display.util are done to not break the public API of this
# module.
from certbot._internal.display.obj import FileDisplay  # pylint: disable=unused-import
from certbot._internal.display.obj import NoninteractiveDisplay  # pylint: disable=unused-import
from certbot._internal.display.obj import SIDE_FRAME  # pylint: disable=unused-import
from certbot._internal.display.util import input_with_timeout  # pylint: disable=unused-import
from certbot._internal.display.util import separate_list_input  # pylint: disable=unused-import
from certbot._internal.display.util import summarize_domain_list  # pylint: disable=unused-import

# These constants are defined this way to make them easier to document with
# Sphinx and to not couple our public docstrings to our internal ones.
OK = obj.OK
"""Display exit code indicating user acceptance."""

CANCEL = obj.CANCEL
"""Display exit code for a user canceling the display."""

# These constants are unused and should be removed in a major release of
# Certbot.
WIDTH = 72

HELP = "help"
"""Display exit code when for when the user requests more help. (UNUSED)"""

ESC = "esc"
"""Display exit code when the user hits Escape (UNUSED)"""


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


def menu(message: str, choices: Union[List[str], List[Tuple[str, str]]],
         default: Optional[int] = None, cli_flag: Optional[str] = None,
         force_interactive: bool = False) -> Tuple[str, int]:
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
               force_interactive: bool = False) -> Tuple[str, str]:
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


def checklist(message: str, tags: List[str], default: Optional[List[str]] = None,
              cli_flag: Optional[str] = None,
              force_interactive: bool = False) -> Tuple[str, List[str]]:
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
                     force_interactive: bool = False) -> Tuple[str, str]:
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


# This class takes a similar approach to the cryptography project to deprecate attributes
# in public modules. See the _ModuleWithDeprecation class here:
# https://github.com/pyca/cryptography/blob/91105952739442a74582d3e62b3d2111365b0dc7/src/cryptography/utils.py#L129
class _DisplayUtilDeprecationModule:
    """
    Internal class delegating to a module, and displaying warnings when attributes
    related to deprecated attributes in the certbot.display.util module.
    """
    def __init__(self, module: ModuleType) -> None:
        self.__dict__['_module'] = module

    def __getattr__(self, attr: str) -> Any:
        if attr in ('FileDisplay', 'NoninteractiveDisplay', 'SIDE_FRAME', 'input_with_timeout',
                    'separate_list_input', 'summarize_domain_list', 'WIDTH', 'HELP', 'ESC'):
            warnings.warn('{0} attribute in certbot.display.util module is deprecated '
                          'and will be removed soon.'.format(attr),
                          DeprecationWarning, stacklevel=2)
        return getattr(self._module, attr)

    def __setattr__(self, attr: str, value: Any) -> None:  # pragma: no cover
        setattr(self._module, attr, value)

    def __delattr__(self, attr: str) -> None:  # pragma: no cover
        delattr(self._module, attr)

    def __dir__(self) -> List[str]:  # pragma: no cover
        return ['_module'] + dir(self._module)


# Patching ourselves to warn about deprecation and planned removal of some elements in the module.
sys.modules[__name__] = cast(ModuleType, _DisplayUtilDeprecationModule(sys.modules[__name__]))
