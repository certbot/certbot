"""Example Let's Encrypt plugins.

For full examples, see `letsencrypt.plugins`.

"""
import zope.interface

from letsencrypt import interfaces
from letsencrypt.plugins import common


class Authenticator(common.Plugin):
    """Example Authenticator."""
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Example Authenticator plugin"

    # Implement all methods from IAuthenticator, remembering to add
    # "self" as first argument, e.g. def prepare(self)...


class Installer(common.Plugin):
    """Example Installer."""
    zope.interface.implements(interfaces.IInstaller)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Example Installer plugin"

    # Implement all methods from IInstaller, remembering to add
    # "self" as first argument, e.g. def get_all_names(self)...
