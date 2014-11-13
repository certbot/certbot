#!/usr/bin/env python

from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder as der_encoder
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA, SHA512
from Crypto.Random import random

class rsa_pk(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('n', univ.Integer()),
        namedtype.NamedType('e', univ.Integer())
    )

def keyid(pem_key_data):
    """Return the hexadecimal keyid for the public key represented by
    pem_key_data.  (This also works when given a private key; the keyid
    returned is then the keyid of the corresponding public key.)  Note that
    this is only valid for an RSA key, not for any other type of public
    key.  The caller must verify that pem_key_data represents a valid RSA
    public or private key.  The keyid calculation is the same one commonly
    performed by certificate authorities, as specified in RFC 5280."""
    r = RSA.importKey(pem_key_data)
    (n, e) = r.publickey().n, r.publickey().e
    # Try to forget the other key parameters (in case it was a private key)
    del r
    pk = rsa_pk()
    pk.setComponentByName("n",n)
    pk.setComponentByName("e",e)
    return SHA.new(der_encoder.encode(pk)).hexdigest()

class POPChallengeResponder(object):
    def __init__(self, sought_id, server_nonce):
        # XXX TODO: possibly we should enforce constraints on the length
        # and structure of the server nonce (e.g. it must be exactly 32
        # lowercase hex digits or we won't respond).
        self.server_nonce = server_nonce
        self.sought_id = sought_id
        self.nonce = random.long_to_bytes(random.getrandbits(256)).encode("hex")
        # XXX TODO: we should find the private key immediately when the
        # responder object is created (if only we knew where to look for
        # it!) -- equivalent to calling self.find_priv() with an appropriate
        # list of candidate files.
        self.privkey = None

    def find_priv(self, candidate_paths):
        """Get the private key corresponding to the sought key ID if it is
        available in any of the files in candidatepaths."""
        for f in candidate_paths:
            try:
                with open(f) as candidate:
                    pem_data = candidate.read(65536)
                    if keyid(pem_data) == self.sought_id:
                        this_key = RSA.importKey(pem_data)
                        if this_key.has_private():
                            # Only private keys are appropriate here, even
                            # though keyid() is defined for both public and
                            # private keys!
                            self.privkey = this_key
                            del this_key
                            return
                        del this_key
            except (IOError, ValueError) as e:
                # If file can't be read or doesn't contain an RSA key,
                # go on to the next file
                continue
        self.privkey = None

    def respond_challenge(self):
        if not self.privkey:
            # If the matching private key wasn't found, the challenge can't
            # be satisfied.
            return None
        to_sign = "chocolate protocol %s %s" % (self.nonce, self.server_nonce)
        # XXX TODO What is an appropriate and safe RSA signature algorithm to
        # use for creating signatures? Is the use of PKCS#1 PSS with SHA-512
        # safe?  Is this implementation free of timing attacks?
        sig = PKCS1_PSS.new(self.privkey).sign(SHA512.new(to_sign))
        # Try to forget the private key now that it's been used.
        self.privkey = None
        return (self.nonce, sig)


# Server-side things

# This makes a challenge given a public key.  To get the public key from
# a particular certifcate:    openssl x509 -in cert.pem -pubkey -noout
def make_challenge(pem_data):
    """Create a proof-of-possession challenge for a particular public key.
    (The caller must verify that pem_data is a valid RSA public key.)"""
    server_nonce = random.long_to_bytes(random.getrandbits(256)).encode("hex")
    return keyid(pem_data), server_nonce

def verify_challenge_response(pubkey, challenge_string, client_nonce, sig):
    """Is sig a valid signature (verified using pubkey) for the combination
    of the specified challenge_string and client_nonce?"""
    try:
        key = RSA.importKey(pubkey)
    except:
        return False
    text = "chocolate protocol %s %s" % (client_nonce, challenge_string)
    return PKCS1_PSS.new(key).verify(SHA512.new(text), sig)
