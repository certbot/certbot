#!/usr/bin/env python

# use OpenSSL to provide CSR-related operations

def parse(csr):
    """Is this CSR syntactically valid?"""
    return True

def goodkey(csr):
    """Does this CSR's public key comply with our CA policy?"""
    return True

def pubkey(csr):
    """Get the public key from this CSR."""
    return ""

def cn(csr):
    """Get the common name from this CSR."""
    return ""

def san(csr):
    """Get the subject alternate names from this CSR."""
    return []

def can_sign(name):
    """Does this CA's policy forbid signing this name via Chocolate DV?"""
    # We could have a regular expression match here, like
    # ([a-z0-9]+\.)+[a-z0-9]+
    # and there is also a list of TLDs to check against to confirm that
    # the name is actually a FQDN.
    if "." not in name: return False
    # Examples of names that are forbidden by policy due to a blacklist.
    if name in ["google.com", "www.google.com"]: return False

def verify(key, data):
    """What string was validly signed by this public key? (or None)"""
    return None

def sign(key, data):
    """Sign this data with this private key.  For client-side use."""
    return ""
