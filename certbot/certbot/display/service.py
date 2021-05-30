from typing import Optional, Any, Union, List, Tuple

import zope.component

from certbot import interfaces


class _DisplayService:
    def __init__(self):
        self.display: Optional[interfaces.IDisplay] = None


_SERVICE = _DisplayService()


def notification(message: str, pause: bool = True, wrap: bool = True,
                 force_interactive: bool = True, decorate: bool = True) -> None:
    get_display().notification(message, pause=pause, wrap=wrap,
                               force_interactive=force_interactive, decorate=decorate)


def menu(message: str, choices: Union[List[Tuple[str, str]], List[str]],
         default: Optional[int] = None, cli_flag: Optional[str] = None,
         force_interactive: bool = False) -> Tuple[str, int]:
    return get_display().menu(message, choices, default=default, cli_flag=cli_flag,
                              force_interactive=force_interactive)


def input(message: str, default: Optional[str] = None, cli_flag: Optional[str] = None,
          force_interactive: bool = False) -> Tuple[str, str]:
    return get_display().input(message, default=default, cli_flag=cli_flag,
                               force_interactive=force_interactive)


def yesno(message: str, yes_label: str ="Yes", no_label: str = "No", default: Optional[bool] = None,
          cli_flag: Optional[str] = None, force_interactive: bool = False) -> bool:
    return get_display().yesno(message, yes_label=yes_label, no_label=no_label, default=default,
                               cli_flag=cli_flag, force_interactive=force_interactive)


def checklist(message: str, tags: List[str], default: Optional[str] = None,
              cli_flag: Optional[str] = None,
              force_interactive: bool = False) -> Tuple[str, List[str]]:
    return get_display().checklist(message, tags, default=default, cli_flag=cli_flag,
                                   force_interactive=force_interactive)


# The following two functions use "Any" for their parameter/output types. Normally interfaces from
# certbot.interfaces would be used, but MyPy will not understand their semantic. These interfaces
# will be removed soon and replaced by ABC classes that will be used also here for type checking.
# TODO: replace Any by actual ABC classes once available

def get_display() -> Any:
    """Get the display utility.

    :return: the display utility
    :rtype: IDisplay
    :raise: ValueError if the display utility is not set

    """
    if not _SERVICE.display:
        raise ValueError("Display service not set, please call "
                         "certbot.display.service.set_display() first to set it.")
    return _SERVICE.display


def set_display(display: Any) -> None:
    """Set the display service.

    :param IDisplay display: the display service

    """
    # This call is done only for retro-compatibility purposes.
    # TODO: Remove this call once zope dependencies are removed from Certbot.
    zope.component.provideUtility(display)

    _SERVICE.display = display
