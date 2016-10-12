"""DNS Resolver for ACME client.
Required only for local validation of 'dns-01' challenges.
"""
import logging

from acme import errors
from acme import util

DNS_REQUIREMENT = 'dnspython>=1.12'

try:
    util.activate(DNS_REQUIREMENT)
    # pragma: no cover
    import dns.exception
    import dns.resolver
    DNS_AVAILABLE = True
except errors.DependencyError:  # pragma: no cover
    DNS_AVAILABLE = False


logger = logging.getLogger(__name__)


def txt_records_for_name(name):
    """Resolve the name and return the TXT records.

    :param unicode name: Domain name being verified.

    :returns: A list of txt records, if empty the name could not be resolved
    :rtype: list of unicode

    """
    if not DNS_AVAILABLE:
        raise errors.DependencyError(
            '{0} is required to use this function'.format(DNS_REQUIREMENT))
    try:
        dns_response = dns.resolver.query(name, 'TXT')
    except dns.resolver.NXDOMAIN as error:
        return []
    except dns.exception.DNSException as error:
        logger.error("Error resolving %s: %s", name, str(error))
        return []

    return [txt_rec.decode("utf-8") for rdata in dns_response
            for txt_rec in rdata.strings]
