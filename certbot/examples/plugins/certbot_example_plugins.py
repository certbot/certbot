"""Example Certbot plugins.

For full examples, see `certbot.plugins`.

"""
from certbot import interfaces
from certbot.plugins import common


class Authenticator(common.Plugin, interfaces.Authenticator):
    """Example Authenticator."""

    description = "Example Authenticator plugin"

    # Implement all methods from Authenticator, remembering to add
    # "self" as first argument, e.g. def prepare(self)...


class Installer(common.Plugin, interfaces.Installer):
    """Example Installer."""

    description = "Example Installer plugin"

    # Implement all methods from Installer, remembering to add
    # "self" as first argument, e.g. def get_all_names(self)...
