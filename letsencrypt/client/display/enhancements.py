"""Let's Encrypt Enhancement Display"""
import logging

import zope.component

from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client.display import display_util


def ask(enhancement):
    """Display the enhancement to the user.

    :param str enhancement: One of the
        :class:`letsencrypt.client.CONFIG.ENHANCEMENTS` enhancements

    :returns: True if feature is desired, False otherwise
    :rtype: bool

    :raises :class:`letsencrypt.client.errors.LetsEncryptClientError`: If
        the enhancement provided is not supported.

    """
    try:
        return _dispatch[enhancement]()
    except KeyError:
        logging.error("Unsupported enhancement given to ask()")
        raise errors.LetsEncryptClientError("Unsupported Enhancement")


def redirect_by_default():
    """Determines whether the user would like to redirect to HTTPS.

    :returns: True if redirect is desired, False otherwise
    :rtype: bool

    """
    choices = [
        ("Easy", "Allow both HTTP and HTTPS access to these sites"),
        ("Secure", "Make all requests redirect to secure HTTPS access"),
    ]

    result = _util(interfaces.IDisplay).menu(
        "Please choose whether HTTPS access is required or optional.",
        choices)

    if result[0] != display_util.OK:
        return False

    return result[1] == 1


_util = zope.component.getUtility


_dispatch = {
    "redirect": redirect_by_default
}