"""Types for representing IP addresses and DNS names internal to Certbot."""
import ipaddress
from abc import abstractmethod
from typing import Any, Iterable

from acme import crypto_util as acme_crypto_util
from cryptography import x509

from certbot import errors

class SAN:
    """A domain or IP address.

    These are Certbot-internal types, independent of the acme module's messages.Identifier.
    """
    @abstractmethod
    def is_wildcard(self) -> bool:
        """Return True if this is a wildcard DNS name."""

class DNSName(SAN):
    """An FQDN or wildcard domain name.

    Raises ConfigurationError if the domain name is syntactically invalid.

    Normalizes inputs by converting to lowercase and removing a trailing dot, if present.
    """
    def __init__(self, dns_name: str) -> None:
        if not isinstance(dns_name, str):
            raise TypeError("tried to initialize DNSName with non-str")
        try:
            dns_name.encode('ascii')
        except UnicodeError:
            raise errors.ConfigurationError("Non-ASCII domain names not supported. "
                                    "To issue for an Internationalized Domain Name, use Punycode.")
        dns_name = dns_name.lower()
        # Remove trailing dot
        dns_name = dns_name.removesuffix(".")

        # Separately check for odd "domains" like "http://example.com" to fail
        # fast and provide a clear error message
        for scheme in ["http", "https"]:  # Other schemes seem unlikely
            if dns_name.startswith("{0}://".format(scheme)):
                raise errors.ConfigurationError(
                    "Requested name {0} appears to be a URL, not a FQDN. "
                    "Try again without the leading \"{1}://\".".format(
                        dns_name, scheme
                    )
                )

        try:
            IPAddress(dns_name)
            raise errors.ConfigurationError(
                "Requested name {0} is an IP address. The Let's Encrypt "
                "certificate authority will not issue certificates for a "
                "bare IP address.".format(dns_name))
        except ValueError:
            pass

        # FQDN checks according to RFC 2181: domain name should be less than 255
        # octets (inclusive). And each label is 1 - 63 octets (inclusive).
        # https://tools.ietf.org/html/rfc2181#section-11
        msg = "Requested domain {0} is not a FQDN because".format(dns_name)
        if len(dns_name) > 255:
            raise errors.ConfigurationError("{0} it is too long.".format(msg))
        labels = dns_name.split('.')
        for l in labels:
            if not l:
                raise errors.ConfigurationError("{0} it contains an empty label.".format(msg))
            if len(l) > 63:
                raise errors.ConfigurationError("{0} label {1} is too long.".format(msg, l))

        self.dns_name = dns_name

    def __str__(self) -> str:
        return self.dns_name

    def __hash__(self) -> int:
        return hash(self.dns_name)

    def __repr__(self) -> str:
        return 'DNS(%s)' % self.dns_name

    def __eq__(self, other: Any) -> bool:
        match other:
            case DNSName():
                return self.dns_name == other.dns_name
            case IPAddress():
                return False
            case _:
                raise TypeError(f"DNSName SAN compared to non-SAN: {type(other)}")

    def is_wildcard(self) -> bool:
        """Return True if this DNS name is a wildcard."""
        return self.dns_name.startswith('*.')

class IPAddress(SAN):
    """An IP address (IPv4 or IPv6).

    Validated upon construction.
    """
    def __init__(self, ip_address: str) -> None:
        self.ip_address = ipaddress.ip_address(ip_address)

    def __str__(self) -> str:
        return str(self.ip_address)

    def __hash__(self) -> int:
        return hash(self.ip_address)

    def __repr__(self) -> str:
        return 'IP(%s)' % self.ip_address

    def __eq__(self, other: Any) -> bool:
        match other:
            case IPAddress():
                return self.ip_address == other.ip_address
            case DNSName():
                return False
            case _:
                raise TypeError(f"IPAddress SAN compared to non-SAN: {type(other)}")

    def is_wildcard(self) -> bool:
        """Always False."""
        return False

def guess(names: Iterable[str]) -> list[SAN]:
    """Turn a list of strings in to a list of SANs based on how they parse."""
    sans: list[SAN] = []
    for name in names:
        try:
            sans.append(IPAddress(name))
        except ValueError:
            sans.append(DNSName(name))
    return sans

def split(sans: Iterable[SAN]) -> tuple[list[DNSName], list[IPAddress]]:
    """Split a list of SANs into a list of DNSNames and one of IPAddress, in that order."""
    domains = []
    ip_addresses = []
    for s in sans:
        match s:
            case IPAddress():
                ip_addresses.append(s)
            case DNSName():
                domains.append(s)
            case _:
                raise TypeError(f"SAN of type {type(s)}")
    return domains, ip_addresses

def join(dns_names: Iterable[DNSName], ip_addresses: Iterable[IPAddress]) -> list[SAN]:
    """Combine a list of DNS names and a list of IP addresses."""
    return list(dns_names) + list(ip_addresses)

def display(sans: Iterable[SAN]) -> str:
    """Return the list of SANs in string form, separated by comma and space."""
    return ", ".join(map(str, sans))

def from_x509(subject: x509.Name, exts: x509.Extensions) -> tuple[list[DNSName], list[IPAddress]]:
    """Get all DNS names and IP addresses, plus the first Common Name from subject.

    The CN will be first in the list, if present. It will always be interpreted
    as a DNS name.

    :param subject: Name of the x509 object, which may include Common Name
    :type subject: `cryptography.x509.Name`
    :param exts: Extensions of the x509 object, which may include SANs
    :type exts: `cryptography.x509.Extensions`

    :returns: Tuple containing a list of DNSNames and a list of IPAddresses
    """
    dns_names, ip_addresses = acme_crypto_util.get_identifiers_from_x509(subject, exts)
    return [DNSName(d) for d in dns_names], [IPAddress(i) for i in ip_addresses]
