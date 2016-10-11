"""DNS Resolver for ACME client.
Required only for local validation of 'dns-01' challenges.
"""
import logging

from acme import util

# This will raise a DependencyError if dnspython is unavailable
util.activate('dnspython>=1.12')

# noqa disables pep8 checking on this lines which is needed because
# pep8 complains about the imports not being at the top of the file
import dns.resolver  # noqa
import dns.exception  # noqa

logger = logging.getLogger(__name__)


def txt_records_for_name(name):
    """Resolve the name and return the TXT records.

    :param unicode name: Domain name being verified.

    :returns: A list of txt records, if empty the name could not be resolved
    :rtype: list of unicode

    """
    try:
        dns_response = dns.resolver.query(name, 'TXT')
    except dns.resolver.NXDOMAIN as error:
        return []
    except dns.exception.DNSException as error:
        logger.error("Error resolving %s: %s", name, str(error))
        return []

    return [txt_rec.decode("utf-8") for rdata in dns_response
            for txt_rec in rdata.strings]
