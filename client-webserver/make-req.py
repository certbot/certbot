#!/usr/bin/env python

# based on M2Crypto unit test written by Toby Allsopp

from M2Crypto import EVP, X509, RSA

def mkreq(names, bits=2048):
    """Return a tuple (key, csr) containing a PEM-formatted private key
    of the specified number of bits and a CSR requesting a certificate for
    the specified DNS names."""
    pk = EVP.PKey()
    x = X509.Request()
    rsa = RSA.gen_key(bits, 65537)
    pk.assign_rsa(rsa)
    key_pem = rsa.as_pem(cipher=None)
    rsa = None # should not be freed here
    x.set_pubkey(pk)
    name = x.get_subject()
    name.CN = names[0]
    extstack = X509.X509_Extension_Stack()
    for n in names:
        ext = X509.new_extension('subjectAltName', 'DNS:%s' % n)
        extstack.push(ext)
    x.add_extensions(extstack)
    x.sign(pk,'sha1')
    assert x.verify(pk)
    pk2 = x.get_pubkey()
    assert x.verify(pk2)
    return key_pem, x.as_pem()
