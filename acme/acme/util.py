"""ACME utilities."""


def map_keys(dikt, func):
    """Map dictionary keys."""
    return {func(key): value for key, value in dikt.items()}

def is_ip(address):
    """ check if this is an IP address"""
    try:
        socket.inet_pton(socket.AF_INET, address)
        # If this line runs it was ip address (ipv4)
        return True
    except socket.error:
        # It wasn't an IPv4 address
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False
