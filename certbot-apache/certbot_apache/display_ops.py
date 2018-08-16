"""Contains UI methods for Apache operations."""
import logging
import os

import zope.component

from certbot import errors
from certbot import interfaces

import certbot.display.util as display_util


logger = logging.getLogger(__name__)


def select_vhost_multiple(vhosts):
    """Select multiple Vhosts to install the certificate for

    :param vhosts: Available Apache VirtualHosts
    :type vhosts: :class:`list` of type `~obj.Vhost`

    :returns: List of VirtualHosts
    :rtype: :class:`list`of type `~obj.Vhost`
    """
    if not vhosts:
        return list()
    tags_list = [vhost.display_repr()+"\n" for vhost in vhosts]
    # Remove the extra newline from the last entry
    if len(tags_list):
        tags_list[-1] = tags_list[-1][:-1]
    code, names = zope.component.getUtility(interfaces.IDisplay).checklist(
        "Which VirtualHosts would you like to install the wildcard certificate for?",
        tags=tags_list, force_interactive=True)
    if code == display_util.OK:
        return_vhosts = _reversemap_vhosts(names, vhosts)
        return return_vhosts
    return []

def _reversemap_vhosts(names, vhosts):
    """Helper function for select_vhost_multiple for mapping string
    representations back to actual vhost objects"""
    return_vhosts = list()

    for selection in names:
        for vhost in vhosts:
            if vhost.display_repr().strip() == selection.strip():
                return_vhosts.append(vhost)
    return return_vhosts

def select_vhost(domain, vhosts):
    """Select an appropriate Apache Vhost.

    :param vhosts: Available Apache VirtualHosts
    :type vhosts: :class:`list` of type `~obj.Vhost`

    :returns: VirtualHost or `None`
    :rtype: `~obj.Vhost` or `None`

    """
    if not vhosts:
        return None
    code, tag = _vhost_menu(domain, vhosts)
    if code == display_util.OK:
        return vhosts[tag]
    else:
        return None

def _vhost_menu(domain, vhosts):
    """Select an appropriate Apache Vhost.

    :param vhosts: Available Apache Virtual Hosts
    :type vhosts: :class:`list` of type `~obj.Vhost`

    :returns: Display tuple - ('code', tag')
    :rtype: `tuple`

    """
    # Free characters in the line of display text (9 is for ' | ' formatting)
    free_chars = display_util.WIDTH - len("HTTPS") - len("Enabled") - 9

    if free_chars < 2:
        logger.debug("Display size is too small for "
                     "certbot_apache.display_ops._vhost_menu()")
        # This runs the edge off the screen, but it doesn't cause an "error"
        filename_size = 1
        disp_name_size = 1
    else:
        # Filename is a bit more important and probably longer with 000-*
        filename_size = int(free_chars * .6)
        disp_name_size = free_chars - filename_size

    choices = []
    for vhost in vhosts:
        if len(vhost.get_names()) == 1:
            disp_name = next(iter(vhost.get_names()))
        elif len(vhost.get_names()) == 0:
            disp_name = ""
        else:
            disp_name = "Multiple Names"

        choices.append(
            "{fn:{fn_size}s} | {name:{name_size}s} | {https:5s} | "
            "{active:7s}".format(
                fn=os.path.basename(vhost.filep)[:filename_size],
                name=disp_name[:disp_name_size],
                https="HTTPS" if vhost.ssl else "",
                active="Enabled" if vhost.enabled else "",
                fn_size=filename_size,
                name_size=disp_name_size)
        )

    try:
        code, tag = zope.component.getUtility(interfaces.IDisplay).menu(
            "We were unable to find a vhost with a ServerName "
            "or Address of {0}.{1}Which virtual host would you "
            "like to choose?".format(domain, os.linesep),
            choices, force_interactive=True)
    except errors.MissingCommandlineFlag:
        msg = (
            "Encountered vhost ambiguity when trying to find a vhost for "
            "{0} but was unable to ask for user "
            "guidance in non-interactive mode. Certbot may need "
            "vhosts to be explicitly labelled with ServerName or "
            "ServerAlias directives.".format(domain))
        logger.warning(msg)
        raise errors.MissingCommandlineFlag(msg)

    return code, tag
