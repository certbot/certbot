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
    choices = []
    for vhost in vhosts:
        if vhost.names == 1:
            disp_name = next(iter(vhost.names))
        elif vhost.names == 0:
            disp_name = ""
        else:
            disp_name = "Multiple Names"

        choices.append(
            "%s | %s | %s | %s" % (
                os.path.basename(vhost.filep),
                disp_name,
                "HTTPS" if vhost.ssl,
                "Enabled" if vhost.enabled)
        )

    code, tag = zope.component.getUtility(interfaces.IDisplay).menu(
        "We were unable to find a vhost with a Servername or Address of %s."
        "Which virtual host would you like to choose?" % domain,
        choices, help_label="More Info", ok_label="Select")

    return code, tag


def _more_info_vhost(vhost):
    zope.component.getUtility(interfaces.IDisplay).notification(
        "Virtual Host Information:{0}{1}".format(
            os.linesep, str(vhost)),
        height=display_util.HEIGHT)