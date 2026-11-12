"""ACME utilities."""
import unicodedata
import punycode
from typing import Any
from typing import Callable
from typing import Mapping


def map_keys(dikt: Mapping[Any, Any], func: Callable[[Any], Any]) -> dict[Any, Any]:
    """Map dictionary keys."""
    return {func(key): value for key, value in dikt.items()}


def is_wildcard_domain(domain: str | bytes) -> bool:
    """Is domain a wildcard domain?

    :param domain: domain to check
    :type domain: `bytes` or `str`

    :returns: True if domain is a wildcard, otherwise, False
    :rtype: bool

    """
    if isinstance(domain, str):
        return domain.startswith("*.")
    return domain.startswith(b"*.")


def normalize_domain(domain: str) -> str:
    """Normalizes a domain name as per the DNS-PERSIST-01 RFC, section 9.2.

    :param domain: domain to normalize
    :type domain: 'str'

    :return: A normalized ASCII domain
    :rtype: str
    """
    # step 1: unicode-aware case folding
    domain = domain.casefold()
    # step 2: Unicode Normalization Form C (NFC)
    domain = unicodedata.normalize('NFC', domain)
    # step 3: punycode
    domain = punycode.convert(domain)
    # step 4: remove trailing dot
    if domain[-1] == '.':
        domain = domain[:-1]
    return domain
