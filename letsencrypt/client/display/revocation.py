"""Revocation UI class."""
import os

import zope.component

from letsencrypt.client import interfaces
from letsencrypt.client.display import util as display_util

util = zope.component.getUtility  # pylint: disable=invalid-name


def choose_certs(certs):
    """Choose a certificate from a menu.

    :param list certs: List of cert dicts.

    :returns: selection (zero-based index)
    :rtype: int

    """
    while True:
        code, selection = _display_certs(certs)

        if code == display_util.OK:
            if confirm_revocation(certs[selection]):
                return selection
        elif code == display_util.HELP:
            more_info_cert(certs[selection])
        else:
            exit(0)


def _display_certs(certs):
    """Display the certificates in a menu for revocation.

    :param list certs: each is a :class:`letsencrypt.client.revoker.Cert`

    :returns: tuple of the form (code, selection) where
        code is a display exit code
        selection is the user's int selection
    :rtype: tuple

    """
    list_choices = [
        "%s | %s | %s" % (
            str(cert.get_cn().ljust(display_util.WIDTH - 39)),
            cert.get_not_before().strftime("%m-%d-%y"),
            "Installed" if cert.installed and cert.installed != ["Unknown"]
            else "") for cert in certs
    ]

    code, tag = util(interfaces.IDisplay).menu(
        "Which certificates would you like to revoke?",
        list_choices, help_label="More Info", ok_label="Revoke",
        cancel_label="Exit")

    return code, tag


def confirm_revocation(cert):
    """Confirm revocation screen.

    :param cert: certificate object
    :type cert: :class:

    :returns: True if user would like to revoke, False otherwise
    :rtype: bool

    """
    text = ("{0}Are you sure you would like to revoke the following "
            "certificate:{0}".format(os.linesep))
    text += cert.pretty_print()
    text += "This action cannot be reversed!"
    return util(interfaces.IDisplay).yesno(text)


def more_info_cert(cert):
    """Displays more info about the cert.

    :param dict cert: cert dict used throughout revoker.py

    """
    text = "{0}Certificate Information:{0}".format(os.linesep)
    text += cert.pretty_print()
    util(interfaces.IDisplay).notification(text, height=display_util.HEIGHT)


def success_revocation(cert):
    """Display a success message.

    :param cert: cert that was revoked
    :type cert: :class:`letsencrypt.client.revoker.Cert`

    """
    util(interfaces.IDisplay).notification(
        "You have successfully revoked the certificate for "
        "%s" % cert.get_cn())
