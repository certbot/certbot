#!/usr/bin/env python

# use OpenSSL to provide CSR-related operations

import subprocess, tempfile, re
import M2Crypto
# we can use tempfile.NamedTemporaryFile() to get tempfiles
# to pass to OpenSSL subprocesses.

def parse(csr):
    """
    Is this CSR syntactically valid? (TODO: remove)

    @type csr: str
    @param csr: PEM-encoded string of the CSR.

    @return: True if M2Crypto can parse the csr,
    False if there is an error parsing it.
    """
    try:
        req = M2Crypto.X509.load_request_string(csr)
        return True
    except Exception:
        return False

def modulusbits(key):
    """How many bits are in the modulus of this key?"""
    bio = M2Crypto.BIO.MemoryBuffer(key)
    pubkey = M2Crypto.RSA.load_pub_key_bio(bio)
    return len(pubkey)

def goodkey(key):
    """Does this public key comply with our CA policy?"""
    bits = modulusbits(key)
    if bits and bits >= 2000:
        return True
    else:
        return False

def csr_goodkey(csr):
    """Does this CSR's embedded public key comply with our CA policy?"""
    if not parse(csr): return False
    key = pubkey(csr)
    return goodkey(key)

def pubkey(csr):
    """
    Get the public key from this Certificate Signing Request.

    @type csr: string
    @param csr: PEM-encoded string of the CSR.
    
    @return: a string of the PEM-encoded public key
    """
    req = M2Crypto.X509.load_request_string(csr)
    return req.get_pubkey().as_pem(None)

def subject(csr):
    """
    Get the X.509 subject from this CSR.
    
    @type csr: string
    @param csr: PEM-encoded string of the CSR.
    
    @return: a string of the subject
    """
    req = M2Crypto.X509.load_request_string(csr)
    return req.get_subject().as_text()

def cn(csr):
    """
    Get the common name from this CSR.  Requires there be exactly one CN
    (of type ASN1_string)

    @type csr: str
    @param csr: PEM-encoded string of the CSR.

    @return: string of the first 
    """

    req = M2Crypto.X509.load_request_string(csr)
    
    # Get an array of CNs
    cns = req.get_subject().get_entries_by_nid(M2Crypto.X509.X509_Name.nid['CN'])

    # If it's not 1, we've got problems (throw error?)
    if len(cns) != 1:
        return None    

    return cns[0].get_data().as_text()

def subject_names(csr):
    """
    Get the cn and subjectAltNames from this CSR.

    @type csr: str
    @param csr: PEM-encoded string of the CSR

    @return: array of strings of subject (CN) and subject
    alternative names (x509 extension)
    """
    names = []
    names.append(cn(csr))
    
    req = M2Crypto.X509.load_request_string(csr)
    for ext in req.get_extensions():            # requires M3Crypto modification
        if ext.get_name() == 'subjectAltName':  # TODO: can we trust this?

            # 'DNS:example.com, DNS:www.example.com'
            sans = ext.get_value().split(',') 
            for san in sans:
                san = san.strip() # remove leading space
                if san.startswith('DNS:'):
                    names.append(san[len('DNS:'):])

            # Don't exit loop - support multiple SAN extensions??

    return names

def can_sign(name):
    """Does this CA's policy forbid signing this name via Chocolate DV?"""
    # We could have a regular expression match here, like
    # ([a-z0-9]+\.)+[a-z0-9]+
    # and there is also a list of TLDs to check against to confirm that
    # the name is actually a FQDN.
    if "." not in name: return False
    # Examples of names that are forbidden by policy due to a blacklist.
    if name in ["google.com", "www.google.com"]: return False
    return True

def verify(key, data):
    """What string was validly signed by this public key? (or None)"""
    # Note: Only relatively short strings will work, so we normally
    # sign a hash of the signed data rather than signing the signed
    # data directly.
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(key)
        tmp.flush()
        out, err = subprocess.Popen(["openssl", "rsautl", "-pubin", "-inkey", tmp.name, "-verify"],shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate(data)
    if out and not err:
        return out
    return None

def sign(key, data):
    """Sign this data with this private key.  For client-side use."""
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(key)
        tmp.flush()
        out, err = subprocess.Popen(["openssl", "rsautl", "-inkey", tmp.name, "-sign"],shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate(data)
    if out and not err:
        return out
    return None

def encrypt(key, data):
    """Encrypt this data with this public key."""
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(key)
        tmp.flush()
        out, err = subprocess.Popen(["openssl", "rsautl", "-pubin", "-inkey", tmp.name, "-encrypt"],shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate(data)
    if out and not err:
        return out
    return None

def issue(csr):
    """Issue the certificate requested by this CSR and return it!"""
    # TODO: a real CA should severely restrict the content of the cert, not
    # just grant what's asked for.  (For example, the CA shouldn't trust
    # all the data in the subject field if it hasn't been validated.)
    # Therefore, we should construct a new CSR from scratch using the
    # parsed-out data from the input CSR, and then pass that to OpenSSL.
    cert = None
    with tempfile.NamedTemporaryFile() as csr_tmp:
        csr_tmp.write(csr)
        csr_tmp.flush()
        with tempfile.NamedTemporaryFile() as cert_tmp:
            ret = subprocess.Popen(["./CA.sh", "-chocolate", csr_tmp.name, cert_tmp.name],shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).wait()
            if ret == 0:
                cert = cert_tmp.read()
    return cert
