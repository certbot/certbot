"""Revocation UI class."""
import os

import zope.component

from letsencrypt.client import interfaces
from letsencrypt.client.display import util as display_util

# Convenience call to make for easier to read lines.
util = zope.component.getUtility  # pylint: disable=invalid-name


def display_certs(certs):
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
    text = ("Are you sure you would like to revoke the following "
            "certificate:{0}{cert}This action cannot be "
            "reversed!".format(os.linesep, cert=cert.pretty_print()))
    return util(interfaces.IDisplay).yesno(text)


def more_info_cert(cert):
    """Displays more info about the cert.

    :param dict cert: cert dict used throughout revoker.py

    """
    text = "Certificate Information:{0}{1}".format(
        os.linesep, cert.pretty_print())
    util(interfaces.IDisplay).notification(text, height=display_util.HEIGHT)


def success_revocation(cert):
    """Display a success message.

    :param cert: cert that was revoked
    :type cert: :class:`letsencrypt.client.revoker.Cert`

    """
    util(interfaces.IDisplay).notification(
        "You have successfully revoked the certificate for "
        "%s" % cert.get_cn())
