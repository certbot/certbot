"""Example Let's Encrypt plugins.

For full examples, see `letsencrypt.client.plugins`.

"""
import zope.interface

from letsencrypt.client import interfaces
from letsencrypt.client.plugins import common


class Authenticator(common.Plugin):
    zope.interface.implements(interfaces.IAuthenticator)

    description = 'Example Authenticator plugin'

    # Implement all methods from IAuthenticator, remembering to add
    # "self" as first argument, e.g. def prepare(self)...


class Installer(common.Plugins):
    zope.interface.implements(interfaces.IInstaller)

    description = 'Example Installer plugin'

    # Implement all methods from IInstaller, remembering to add
    # "self" as first argument, e.g. def get_all_names(self)...
