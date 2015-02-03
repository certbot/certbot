"""Let's Encrypt client crypto utility functions

.. todo:: Make the transition to use PSS rather than PKCS1_v1_5 when the server
    is capable of handling the signatures.

"""
import binascii
import logging
import time

from Crypto import Random
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_v1_5

import M2Crypto

from letsencrypt.client import CONFIG
from letsencrypt.client import le_util


def create_sig(msg, key_str, nonce=None, nonce_len=CONFIG.NONCE_SIZE):
    """Create signature with nonce prepended to the message.

    .. todo:: Protect against crypto unicode errors... is this sufficient?
        Do I need to escape?

    :param str msg: Message to be signed

    :param str key_str: Key in string form. Accepted formats
        are the same as for `Crypto.PublicKey.RSA.importKey`.

    :param nonce: Nonce to be used. If None, nonce of `nonce_len` size
                  will be randomly generated.
    :type nonce: str or None

    :param int nonce_len: Size of the automatically generated nonce.

    :returns: Signature.
    :rtype: dict

    """
    msg = str(msg)
    key = Crypto.PublicKey.RSA.importKey(key_str)
    nonce = Random.get_random_bytes(nonce_len) if nonce is None else nonce

    msg_with_nonce = nonce + msg
    hashed = Crypto.Hash.SHA256.new(msg_with_nonce)
    signature = Crypto.Signature.PKCS1_v1_5.new(key).sign(hashed)

    logging.debug("%s signed as %s", msg_with_nonce, signature)

    n_bytes = binascii.unhexlify(_leading_zeros(hex(key.n)[2:].rstrip("L")))
    e_bytes = binascii.unhexlify(_leading_zeros(hex(key.e)[2:].rstrip("L")))

    return {
        "nonce": le_util.jose_b64encode(nonce),
        "alg": "RS256",
        "jwk": {
            "kty": "RSA",
            "n": le_util.jose_b64encode(n_bytes),
            "e": le_util.jose_b64encode(e_bytes),
        },
        "sig": le_util.jose_b64encode(signature),
    }


def _leading_zeros(arg):
    if len(arg) % 2:
        return "0" + arg
    return arg


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

    m2_cert = M2Crypto.X509.X509()
    m2_cert.set_pubkey(pubkey)
    m2_cert.set_serial_number(1337)
    m2_cert.set_version(2)

    current_ts = long(time.time() if not_before is None else not_before)
    current = M2Crypto.ASN1.ASN1_UTCTIME()
    current.set_time(current_ts)
    expire = M2Crypto.ASN1.ASN1_UTCTIME()
    expire.set_time(current_ts + validity)
    m2_cert.set_not_before(current)
    m2_cert.set_not_after(expire)

    subject = m2_cert.get_subject()
    subject.C = "US"
    subject.ST = "Michigan"
    subject.L = "Ann Arbor"
    subject.O = "University of Michigan and the EFF"
    subject.CN = domains[0]
    m2_cert.set_issuer(m2_cert.get_subject())

    if len(domains) > 1:
        m2_cert.add_ext(M2Crypto.X509.new_extension(
            "basicConstraints", "CA:FALSE"))
        m2_cert.add_ext(M2Crypto.X509.new_extension(
            "subjectAltName", ", ".join(["DNS:%s" % d for d in domains])))

    m2_cert.sign(pubkey, "sha256")
    assert m2_cert.verify(pubkey)
    assert m2_cert.verify()
    # print check_purpose(,0
    return m2_cert.as_pem()


def b64_cert_to_pem(b64_der_cert):
    """Convert JOSE Base-64 encoded DER cert to PEM."""
    return M2Crypto.X509.load_cert_der_string(
        le_util.jose_b64decode(b64_der_cert)).as_pem()
