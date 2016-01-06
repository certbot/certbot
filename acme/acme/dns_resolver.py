"""DNS Resolver for ACME client.
Required only for local validation of 'dns-01' challenges.
"""
import logging

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

def txt_records_for_name(name):
    """Resolve the name and return the TXT records.

    :param unicode name: Domain name being verified.

    :returns: A list of txt records, if empty the name could not be resolved
    :rtype: list of unicode

    """
    try:
        dns_response = dns.resolver.query(name, 'TXT')
    except ImportError as error:  # pragma: no cover
        raise ImportError("Local validation for 'dns-01' challenges requires "
                          "'dnspython'")
    except dns.exception.DNSException as error:
        logger.error("Unable to resolve %s: %s", name, str(error))
        return []
    return [txt_rec for rdata in dns_response for txt_rec in rdata.strings]
