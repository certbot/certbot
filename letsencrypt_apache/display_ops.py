"""Contains UI methods for Apache operations."""
import os
import zope.component

from letsencrypt import interfaces

import letsencrypt.display.util as display_util


def select_vhost(domain, vhosts):
    """Select an appropriate Apache Vhost.

    :param vhosts: Available Apache Virtual Hosts
    :type vhosts: :class:`list` of type `~obj.Vhost`

    :returns: VirtualHost
    :rtype: `~obj.Vhost`

    """
    if not vhosts:
        return None
    while True:
        code, tag = _vhost_menu(domain, vhosts)
        if code == display_util.HELP:
            _more_info_vhost(vhosts[tag])
        elif code == display_util.OK:
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
    filename_size = 24
    disp_name_size = 17
    choices = []
    for vhost in vhosts:
        if len(vhost.names) == 1:
            disp_name = next(iter(vhost.names))
        elif len(vhost.names) == 0:
            disp_name = ""
        else:
            disp_name = "Multiple Names"

        choices.append(
            "{0:{4}s} | {1:{5}s} | {2:5s} | {3:7s}".format(
                os.path.basename(vhost.filep)[:filename_size],
                disp_name[:disp_name_size],
                "HTTPS" if vhost.ssl else "",
                "Enabled" if vhost.enabled else "",
                filename_size,
                disp_name_size)
        )

    code, tag = zope.component.getUtility(interfaces.IDisplay).menu(
        "We were unable to find a vhost with a ServerName or Address of {0}.{1}"
        "Which virtual host would you like to choose?".format(
            domain, os.linesep),
        choices, help_label="More Info", ok_label="Select")

    return code, tag


def _more_info_vhost(vhost):
    zope.component.getUtility(interfaces.IDisplay).notification(
        "Virtual Host Information:{0}{1}{0}{2}".format(
            os.linesep, "-" * (display_util.WIDTH - 4), str(vhost)),
        height=display_util.HEIGHT)
