"""Certbot Enhancement Display"""
import logging

import zope.component

from certbot import errors
from certbot import interfaces
from certbot.display import util as display_util


logger = logging.getLogger(__name__)

# Define a helper function to avoid verbose code
util = zope.component.getUtility


def ask(enhancement):
    """Display the enhancement to the user.

    :param str enhancement: One of the
        :class:`certbot.CONFIG.ENHANCEMENTS` enhancements

    :returns: True if feature is desired, False otherwise
    :rtype: bool

    :raises .errors.Error: if the enhancement provided is not supported

    """
    try:
        # Call the appropriate function based on the enhancement
        return DISPATCH[enhancement]()
    except KeyError:
        logger.error("Unsupported enhancement given to ask(): %s", enhancement)
        raise errors.Error("Unsupported Enhancement")


def redirect_by_default():
    """Determines whether the user would like to redirect to HTTPS.

    :returns: True if redirect is desired, False otherwise
    :rtype: bool

    """
    choices = [
        ("No redirect", "Make no further changes to the webserver configuration."),
        ("Redirect", "Make all requests redirect to secure HTTPS access. "
            "Choose this for new sites, or if you're confident your site works on HTTPS. "
            "You can undo this change by editing your web server's configuration."),
    ]

    code, selection = util(interfaces.IDisplay).menu(
        "Please choose whether or not to redirect HTTP traffic to HTTPS, removing HTTP access.",
        choices, default=0,
        cli_flag="--redirect / --no-redirect", force_interactive=True)

    if code != display_util.OK:
        return False

    return selection == 1


DISPATCH = {
    "redirect": redirect_by_default
}
