"""Types for representing IP addresses and DNS names internal to Certbot."""
import ipaddress

class SAN:
    """A domain or IP address.

    These are Certbot-internal types, independent of the acme module's messages.Identifier.
    """

class DNSName(SAN):
    """An FQDN or wildcard domain name.

    Not validated upon construction.
    """
    # TODO: validate upon construction, making sure user-friendly errors are generated.
    def __init__(self, dns_name):
        self.dns_name = dns_name

    def __str__(self):
        return self.dns_name

    def __hash__(self):
        return hash(self.dns_name)

    def __repr__(self):
        return 'DNS(%s)' % self.dns_name

    def __eq__(self, other):
        if not issubclass(type(other), SAN):
            raise TypeError(f"DNSName SAN compared to non-SAN: {type(other)}")
        return self.dns_name == other.dns_name

    def is_wildcard(self):
        """Return True if this DNS name is a wildcard."""
        return self.dns_name.startswith('*.')

class IPAddress(SAN):
    """An IP address (IPv4 or IPv6).

    Validated upon construction.
    """
    def __init__(self, ip_address: str):
        self.ip_address = ipaddress.ip_address(ip_address)

    def __str__(self):
        return str(self.ip_address)

    def __hash__(self):
        return hash(self.ip_address)

    def __repr__(self):
        return 'IP(%s)' % self.ip_address

    def __eq__(self, other):
        if not issubclass(type(other), SAN):
            raise TypeError(f"IPAddress SAN compared to non-SAN: {type(other)}")
        return self.ip_address == other.ip_address

    def is_wildcard(self):
        """Always False."""
        return False

def split(sans: list[SAN]) -> (list[DNSName], list[IPAddress]):
    """Split a list of SANs into a list of DNSNames and one of IPAddress, in that order."""
    domains = []
    ip_addresses = []
    for s in sans:
        match s:
            case IPAddress():
                ip_addresses.append(s.ip_address)
            case DNSName():
                domains.append(s.dns_name)
            case _:
                raise TypeError(f"SAN of type {type(s)}")
    return domains, ip_addresses
