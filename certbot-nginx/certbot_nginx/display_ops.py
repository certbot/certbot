"""Contains UI methods for Nginx operations."""
import logging
import os

import zope.component

from certbot import errors
from certbot import interfaces

import certbot.display.util as display_util


logger = logging.getLogger(__name__)


def select_vhost_multiple(vhosts):
    """Select multiple Vhosts to install the certificate for
    :param vhosts: Available Nginx VirtualHosts
    :type vhosts: :class:`list` of type `~obj.Vhost`
    :returns: List of VirtualHosts
    :rtype: :class:`list`of type `~obj.Vhost`
    """
    if not vhosts:
        return list()
    tags_list = [vhost.display_repr() for vhost in vhosts]
    while True:
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
            if vhost.display_repr() == selection:
                return_vhosts.append(vhost)
    return return_vhosts
