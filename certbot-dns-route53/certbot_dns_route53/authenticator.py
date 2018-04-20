"""Shim around `~certbot_dns_route53.dns_route53` for backwards compatibility."""
import warnings

import zope.interface

from certbot import interfaces
from certbot_dns_route53 import dns_route53


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_route53.Authenticator):
    """Shim around `~certbot_dns_route53.dns_route53.Authenticator` for backwards compatibility."""

    hidden = True

    def __init__(self, *args, **kwargs):
        warnings.warn("The 'authenticator' module was renamed 'dns_route53'",
                      DeprecationWarning)
        super(Authenticator, self).__init__(*args, **kwargs)
