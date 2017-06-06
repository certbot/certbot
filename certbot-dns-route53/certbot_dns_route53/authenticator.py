"""Shim around `~certbot_dns_route53.dns_route53` for backwards compatibility."""
import warnings

from certbot_dns_route53 import dns_route53


class Authenticator(dns_route53.Authenticator):
    """Shim around `~certbot_dns_route53.dns_route53.Authenticator` for backwards compatibility."""
    def __init__(self, *args, **kwargs):
        warnings.warn("The 'authenticator' module was renamed 'dns_route53'",
                      DeprecationWarning)
        super(Authenticator, self).__init__(*args, **kwargs)
