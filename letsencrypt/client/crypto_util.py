"""Let's Encrypt client crypto utility functions.

.. todo:: Make the transition to use PSS rather than PKCS1_v1_5 when the server
    is capable of handling the signatures.

"""
import time

import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_v1_5

import M2Crypto


def make_csr(key_str, domains):
    """Generate a CSR.

    :param str key_str: RSA key.
    :param list domains: Domains included in the certificate.

    :returns: new CSR in PEM and DER form containing all domains
    :rtype: tuple

    """
    assert domains, "Must provide one or more hostnames for the CSR."
    rsa_key = M2Crypto.RSA.load_key_string(key_str)
    pubkey = M2Crypto.EVP.PKey()
    pubkey.assign_rsa(rsa_key)

    csr = M2Crypto.X509.Request()
    csr.set_pubkey(pubkey)
    name = csr.get_subject()
    name.C = "US"
    name.ST = "Michigan"
    name.L = "Ann Arbor"
    name.O = "EFF"
    name.OU = "University of Michigan"
    name.CN = domains[0]

    extstack = M2Crypto.X509.X509_Extension_Stack()
    ext = M2Crypto.X509.new_extension(
        "subjectAltName", ", ".join("DNS:%s" % d for d in domains))

    extstack.push(ext)
    csr.add_extensions(extstack)
    csr.sign(pubkey, "sha256")
    assert csr.verify(pubkey)
    pubkey2 = csr.get_pubkey()
    assert csr.verify(pubkey2)
    return csr.as_pem(), csr.as_der()


# WARNING: the csr and private key file are possible attack vectors for TOCTOU
# We should either...
# A. Do more checks to verify that the CSR is trusted/valid
# B. Audit the parsing code for vulnerabilities

def valid_csr(csr):
    """Validate CSR.

    Check if `csr` is a valid CSR for the given domains.

    :param str csr: CSR in PEM.

    :returns: Validity of CSR.
    :rtype: bool

    """
    try:
        csr_obj = M2Crypto.X509.load_request_string(csr)
        return bool(csr_obj.verify(csr_obj.get_pubkey()))
    except M2Crypto.X509.X509Error:
        return False


def csr_matches_pubkey(csr, privkey):
    """Does private key correspond to the subject public key in the CSR?

    :param str csr: CSR in PEM.
    :param str privkey: Private key file contents

    :returns: Correspondence of private key to CSR subject public key.
    :rtype: bool

    """
    csr_obj = M2Crypto.X509.load_request_string(csr)
    privkey_obj = M2Crypto.RSA.load_key_string(privkey)
    return csr_obj.get_pubkey().get_rsa().pub() == privkey_obj.pub()


def make_key(bits):
    """Generate PEM encoded RSA key.

    :param int bits: Number of bits, at least 1024.

    :returns: new RSA key in PEM form with specified number of bits
    :rtype: str

    """
    return Crypto.PublicKey.RSA.generate(bits).exportKey(format="PEM")


def valid_privkey(privkey):
    """Is valid RSA private key?

    :param str privkey: Private key file contents

    :returns: Validity of private key.
    :rtype: bool

    """
    try:
        return bool(M2Crypto.RSA.load_key_string(privkey).check_key())
    except M2Crypto.RSA.RSAError:
        return False


def make_ss_cert(key_str, domains, not_before=None,
                 validity=(7 * 24 * 60 * 60)):
    """Returns new self-signed cert in PEM form.

    Uses key_str and contains all domains.

    """
    assert domains, "Must provide one or more hostnames for the CSR."

    rsa_key = M2Crypto.RSA.load_key_string(key_str)
    pubkey = M2Crypto.EVP.PKey()
    pubkey.assign_rsa(rsa_key)

    cert = M2Crypto.X509.X509()
    cert.set_pubkey(pubkey)
    cert.set_serial_number(1337)
    cert.set_version(2)

    current_ts = long(time.time() if not_before is None else not_before)
    current = M2Crypto.ASN1.ASN1_UTCTIME()
    current.set_time(current_ts)
    expire = M2Crypto.ASN1.ASN1_UTCTIME()
    expire.set_time(current_ts + validity)
    cert.set_not_before(current)
    cert.set_not_after(expire)

    subject = cert.get_subject()
    subject.C = "US"
    subject.ST = "Michigan"
    subject.L = "Ann Arbor"
    subject.O = "University of Michigan and the EFF"
    subject.CN = domains[0]
    cert.set_issuer(cert.get_subject())

    if len(domains) > 1:
        cert.add_ext(M2Crypto.X509.new_extension(
            "basicConstraints", "CA:FALSE"))
        cert.add_ext(M2Crypto.X509.new_extension(
            "subjectAltName", ", ".join(["DNS:%s" % d for d in domains])))

    cert.sign(pubkey, "sha256")
    assert cert.verify(pubkey)
    assert cert.verify()
    # print check_purpose(,0
    return cert.as_pem()


def get_sans_from_csr(csr):
    """Get list of Subject Alternative Names from signing request.

    :param str csr: Certificate Signing Request in PEM format (must contain
        one or more subjectAlternativeNames, or the function will fail,
        raising ValueError)

    :returns: List of referenced subject alternative names
    :rtype: list
    """
    # TODO: This is a temporary solution involving parsing the .as_text()
    #       output because there doesn't seem to be a built-in feature in
    #       any Python cryptography module that performs this function.
    #       In the future we should try to replace this with a more direct
    #       use of relevant OpenSSL or other X509-parsing APIs.
    req = M2Crypto.X509.load_request_string(csr)
    text = req.as_text().split("\n")
    if (len(text) < 2 or text[0] != "Certificate Request:" or
            text[1] != "    Data:"):
        raise ValueError("Unable to parse CSR")
    text = text[2:]
    while text and text[0] != "        Attributes:":
        text = text[1:]
    while text and text[0] != "        Requested Extensions:":
        text = text[1:]
    while text and text[0] != "            X509v3 Subject Alternative Name: ":
        text = text[1:]
    text = text[1:]
    if not text:
        raise ValueError("Unable to parse CSR")

    # XXX: This might break for non-ASCII hostnames and for non-DNS
    #      names in SANs.  There is also a parser safety concern about
    #      whether the CSR's contents are interpreted in the same way
    #      by this code and by any other code that might interpret the
    #      CSR for a different purpose.  Also, if there is a non-DNS
    #      name in a SAN that contains ", DNS:example.com, " as part
    #      of the name (for example, in the comment field of an e-mail
    #      SAN), this code will be fooled into returning that name as
    #      if it were an additional DNS SAN.  The severity of this is
    #      unclear, because the client currently presents the results of
    #      this list to the user for confirmation before requesting the
    #      cert from the server.
    return [san.split(":")[1] for san in text[0].strip().split(", ")
            if san.startswith("DNS:")]
