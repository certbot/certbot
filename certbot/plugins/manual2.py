"""Manual authenticator plugin"""
import logging
import zope.component
import zope.interface

from certbot import interfaces
from certbot.plugins import common

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Manual authenticator

    This plugin allows the user to perform the domain validation
    challenge(s) themselves. This can be done either be done manually
    by the user or through shell scripts provided to Certbot.

    """

    description = "Manual configuration or run your own shell scripts"
    hidden = True
    long_description = (
        "Authenticate through manual configuration or custom shell scripts. "
        "When using shell scripts, an authenticator script must be provided. "
        "The environment variables available to this script are "
        "$CERTBOT_DOMAIN which contains the domain being authenticated, "
        "$CERTBOT_VALIDATION which is the validation string, and "
        "$CERTBOT_TOKEN which is the filename of the resource requested when "
        "performing an HTTP-01 challenge. An additional cleanup script can "
        "also be provided and can use the additional variable "
        "$CERTBOT_AUTH_OUTPUT which contains the stdout output from the auth "
        "script."
    )
