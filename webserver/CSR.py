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

def verify(key, data):
    """What string was validly signed by this public key? (or None)"""
    return None

def sign(key, data):
    """Sign this data with this private key.  For client-side use."""
    return ""
