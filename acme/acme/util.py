"""ACME utilities."""
import ipaddress

def map_keys(dikt, func):
    """Map dictionary keys."""
    return {func(key): value for key, value in dikt.items()}

def is_ip(address):
    """ check if this is an IP address"""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        # It wasn't ip
        return False
