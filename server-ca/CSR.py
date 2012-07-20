#!/usr/bin/env python

# use OpenSSL to provide CSR-related operations

import site, os
assert os.path.exists("../m3/lib/python"), "\nPlease install m3crypto into ../m3/lib/python by running\nmkdir -p ../m3/lib/python; PYTHONPATH=../m3/lib/python python setup.py install --home=../m3\nfrom inside the m3crypto directory."
site.addsitedir("../m3/lib/python")
import subprocess, re
from tempfile import NamedTemporaryFile as temp
import M2Crypto
from distutils.version import LooseVersion
assert LooseVersion(M2Crypto.version) >= LooseVersion("0.22")
import hashlib
import blacklists
# we can use temp() to get tempfiles to pass to OpenSSL subprocesses.

from CONFIG import min_key_size

forbidden_moduli = blacklists.forbidden_moduli()
forbidden_names = blacklists.forbidden_names()

def parse(csr):
    """
    Is this CSR syntactically valid? (TODO: remove)

    @type csr: str
    @param csr: PEM-encoded string of the CSR.

    @return: True if M2Crypto can parse the csr,
    False if there is an error parsing it.
    """
    try:
        csr = str(csr)
        req = M2Crypto.X509.load_request_string(csr)
        return True
    except Exception, e:
        return False

def modulusbits(key):
    key = str(key)
    """How many bits are in the modulus of this key?"""
    bio = M2Crypto.BIO.MemoryBuffer(key)
    pubkey = M2Crypto.RSA.load_pub_key_bio(bio)
    return len(pubkey)

def goodkey(key):
    """Does this public key comply with our CA policy?"""
    key = str(key)
    bits = modulusbits(key)
    if bits and bits >= min_key_size and not blacklisted(key):
        return True
    else:
        return False

def blacklisted(key):
    """Is this key blacklisted?"""
    # There is also a modulus function that uses M2Crypto.m2.rsa_get_n
    # instead of EVP.PKey, but it seems to erroneously prepend the exponent
    # to the modulus or something.
    bio = M2Crypto.BIO.MemoryBuffer(key)
    pubkey = M2Crypto.RSA.load_pub_key_bio(bio)
    pkey = M2Crypto.EVP.PKey()
    pkey.assign_rsa(pubkey)
    modulus = pkey.get_modulus()
    # The modulus is now in hexadecimal, all uppercase.
    modulus = hashlib.sha1("Modulus=%s\n" % modulus).hexdigest()[20:]
    # This is the format in which moduli are represented by the
    # openssl-blacklist package (using a hash of the literal output
    # of the openssl -rsa -modulus -pubin -noout command, including
    # newline).
    return modulus in forbidden_moduli

def csr_goodkey(csr):
    """Does this CSR's embedded public key comply with our CA policy?"""
    csr = str(csr)
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
    csr = str(csr)
    req = M2Crypto.X509.load_request_string(csr)
    return req.get_pubkey().get_rsa().as_pem(None)

def subject(csr):
    """
    Get the X.509 subject from this CSR.
    
    @type csr: string
    @param csr: PEM-encoded string of the CSR.
    
    @return: a string of the subject
    """
    csr = str(csr)
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
    csr = str(csr)
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
    csr = str(csr)
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
    name = str(name)
    if "." not in name: return False
    # Names that are forbidden by policy due to a blacklist.
    return name not in forbidden_names

def verify(key, data, signature):
    """
    Given a public key, some data, and its signature, 
    verify the signature.
    
    @type key: str
    @param key: PEM-encoded string of the public key.

    @type data: str
    @param data: The data (before being hashed; we will use sha256 here)

    @type signature: str
    @param signature: binary string of the signature

    @return: True if the signature checks out, False otherwise. 
    """
    key = str(key)
    data = str(data)
    signature = str(signature)
    bio = M2Crypto.BIO.MemoryBuffer(key)
    pubkey = M2Crypto.RSA.load_pub_key_bio(bio)
    try:
        res = pubkey.verify(hashlib.sha256(data).digest(), signature, 'sha256')
    except M2Crypto.RSA.RSAError:
        return False
    return (res == 1) 

def encrypt(key, data):
    """
    Encrypt this data with this public key.

    @type key: str
    @param key: PEM-encoded string of the public key

    @type data: str
    @param data: The data to be encrypted. 

    @return: binary string of the encrypted value, using PKCS1_OAEP_PADDING
    """
    key = str(key)
    data = str(data)
    bio = M2Crypto.BIO.MemoryBuffer(key)
    pubkey = M2Crypto.RSA.load_pub_key_bio(bio)
    return pubkey.public_encrypt(data, M2Crypto.RSA.pkcs1_oaep_padding)

def issue(csr, subjects):
    """Issue a certificate requested by CSR, specifying the subject names
    indicated in subjects, and return the certificate.  Calls to this
    function should be guarded with a lock to ensure that the calls never
    overlap."""
    if not subjects:
        return None
    csr = str(csr)
    subjects = [str(s) for s in subjects]
    for s in subjects:
        if ":" in s or "," in s or " " in s or "\n" in s or "\r" in s:
            # We should already have validated the names to be issued a
            # long time ago, but this is an extra sanity check to make
            # sure that the cert issuing process can't be corrupted by
            # attempting to issue certs for names with special characters.
            return None
    cert = None
    # We need three temporary files: for the CSR, for the extension config
    # file, and for the resulting certificate.
    with temp() as csr_tmp, temp() as ext_tmp, temp() as cert_tmp:
        csr_tmp.write(csr)
        csr_tmp.flush()
        dn = "/CN=%s" % subjects[0]
        ext_tmp.write("""
basicConstraints=CA:FALSE
keyUsage=digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
nsComment = "Chocolatey"
""")
        if subjects[1:]:
            san_line = "subjectAltName="
            san_line += ",".join("DNS:%s" % n for n in subjects[1:]) + "\n"
            ext_tmp.write(san_line)
        ext_tmp.flush()
        ret = subprocess.Popen(["./CA.sh", "-complete", dn, ext_tmp.name, csr_tmp.name, cert_tmp.name],shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE).wait()
        if ret == 0:
            cert = cert_tmp.read()
    return cert
