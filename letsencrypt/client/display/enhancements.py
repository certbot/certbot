"""Let's Encrypt Enhancement Display"""
import logging

import zope.component

from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client.display import display_util


class EnhanceDisplay(object):
    """Class used to display various enhancements.

    .. note::This is not a subclass of Display. It merely uses Display as a
        component.

    :ivar displayer: Display singleton
    :type displayer: :class:`letsencrypt.client.interfaces.IDisplay

    :ivar dict dispatch: Dict mapping enhancements to functions

    """
    def __init__(self):
        self.displayer = zope.component.getUtility(interfaces.IDisplay)

        self.dispatch = {
            "redirect": self.redirect_by_default,
        }

    def ask(self, enhancement):
        """Display the enhancement to the user.

        :param str enhancement: One of the
            :class:`letsencrypt.client.CONFIG.ENHANCEMENTS` enhancements

        :returns: True if feature is desired, False otherwise
        :rtype: bool

        :raises :class:`letsencrypt.client.errors.LetsEncryptClientError`: If
            the enhancement provided is not supported.

        """
        try:
            return self.dispatch[enhancement]
        except KeyError:
            logging.error("Unsupported enhancement given to ask()")
            raise errors.LetsEncryptClientError("Unsupported Enhancement")

    def redirect_by_default(self):
        """Determines whether the user would like to redirect to HTTPS.

        :returns: True if redirect is desired, False otherwise
        :rtype: bool

        """
        choices = [
            ("Easy", "Allow both HTTP and HTTPS access to these sites"),
            ("Secure", "Make all requests redirect to secure HTTPS access")]

        result = self.displayer.menu(
            "Please choose whether HTTPS access is required or optional.",
            choices, "Please enter the appropriate number")

        if result[0] != display_util.OK:
            return False

        # different answer for each type of display
        return str(result[1]) == "Secure" or result[1] == 1