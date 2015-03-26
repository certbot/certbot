"""Example Let's Encrypt plugins."""
import zope.interface

from letsencrypt.client import interfaces


class Authenticator(object):
    zope.interface.implements(interfaces.IAuthenticator)

    description = 'Example Authenticator plugin'

    def __init__(self, config):
        self.config = config

    # Implement all methods from IAuthenticator, remembering to add
    # "self" as first argument, e.g. def prepare(self)...
