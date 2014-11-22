import binascii
import hashlib
import time

from Crypto import Random
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_v1_5

import M2Crypto

from letsencrypt.client import CONFIG
from letsencrypt.client import le_util


def b64_cert_to_pem(b64_der_cert):
    return M2Crypto.X509.load_cert_der_string(
        le_util.b64_url_dec(b64_der_cert)).as_pem()


def create_sig(msg, key_file, signer_nonce=None,
               signer_nonce_len=CONFIG.NONCE_SIZE):
    # DOES prepend signer_nonce to message
    # TODO: Change this over to M2Crypto... PKey
    # Protect against crypto unicode errors... is this sufficient?
    # Do I need to escape?
    msg = str(msg)
    key = Crypto.PublicKey.RSA.importKey(open(key_file).read())
    if signer_nonce is None:
        signer_nonce = Random.get_random_bytes(signer_nonce_len)
    hashed = Crypto.Hash.SHA256.new(signer_nonce + msg)
    signer = Crypto.Signature.PKCS1_v1_5.new(key)
    signature = signer.sign(hashed)
    #print "signing:", signer_nonce + msg
    #print "signature:", signature
    n_bytes = binascii.unhexlify(leading_zeros(hex(key.n)[2:].replace("L", "")))
    e_bytes = binascii.unhexlify(leading_zeros(hex(key.e)[2:].replace("L", "")))
    n_encoded = le_util.b64_url_enc(n_bytes)
    e_encoded = le_util.b64_url_enc(e_bytes)
    signer_nonce_encoded = le_util.b64_url_enc(signer_nonce)
    sig_encoded = le_util.b64_url_enc(signature)
    jwk = {"kty": "RSA", "n": n_encoded, "e": e_encoded}
    signature = {
        "nonce": signer_nonce_encoded,
        "alg": "RS256",
        "jwk": jwk,
        "sig": sig_encoded
    }
    # return json.dumps(signature)
    return signature


def leading_zeros(arg):
    if len(arg) % 2:
        return "0" + arg
    return arg


def sha256(arg):
    return hashlib.sha256(arg).hexdigest()


# based on M2Crypto unit test written by Toby Allsopp
def make_key(bits=CONFIG.RSA_KEY_SIZE):
    """
    Returns new RSA key in PEM form with specified bits
    """
    #Python Crypto module doesn't produce any stdout
    key = Crypto.PublicKey.RSA.generate(bits)
    #rsa = M2Crypto.RSA.gen_key(bits, 65537)
    #key_pem = rsa.as_pem(cipher=None)
    #rsa = None # should not be freed here

    return key.exportKey(format='PEM')


def make_csr(key_file, domains):
    """
    Returns new CSR in PEM and DER form using key_file containing all domains
    """
    assert domains, "Must provide one or more hostnames for the CSR."
    rsa_key = M2Crypto.RSA.load_key(key_file)
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
        'subjectAltName', ", ".join(["DNS:%s" % d for d in domains]))

    extstack.push(ext)
    csr.add_extensions(extstack)
    csr.sign(pubkey, 'sha256')
    assert csr.verify(pubkey)
    pubkey2 = csr.get_pubkey()
    assert csr.verify(pubkey2)
    return csr.as_pem(), csr.as_der()


def make_ss_cert(key_file, domains):
    """Returns new self-signed cert in PEM form.

    Uses key_file and contains all domains.
    """
    assert domains, "Must provide one or more hostnames for the CSR."
    rsa_key = M2Crypto.RSA.load_key(key_file)
    pubkey = M2Crypto.EVP.PKey()
    pubkey.assign_rsa(rsa_key)

    cert = M2Crypto.X509.X509()
    cert.set_pubkey(pubkey)
    cert.set_serial_number(1337)
    cert.set_version(2)

    current_ts = long(time.time())
    current = M2Crypto.ASN1.ASN1_UTCTIME()
    current.set_time(current_ts)
    expire = M2Crypto.ASN1.ASN1_UTCTIME()
    expire.set_time((7 * 24 * 60 * 60) + current_ts)
    cert.set_not_before(current)
    cert.set_not_after(expire)

    name = cert.get_subject()
    name.C = "US"
    name.ST = "Michigan"
    name.L = "Ann Arbor"
    name.O = "University of Michigan and the EFF"
    name.CN = domains[0]
    cert.set_issuer(cert.get_subject())

    cert.add_ext(M2Crypto.X509.new_extension('basicConstraints', 'CA:FALSE'))
    #cert.add_ext(M2Crypto.X509.new_extension(
    #    'extendedKeyUsage', 'TLS Web Server Authentication'))
    cert.add_ext(M2Crypto.X509.new_extension(
        'subjectAltName', ", ".join(["DNS:%s" % d for d in domains])))

    cert.sign(pubkey, 'sha256')
    assert cert.verify(pubkey)
    assert cert.verify()
    #print check_purpose(,0
    return cert.as_pem()


def get_cert_info(filename):
    # M2Crypto Library only supports RSA right now
    cert = M2Crypto.X509.load_cert(filename)

    try:
        san = cert.get_ext("subjectAltName").get_value()
    except:
        san = ""

    return {
        "not_before": cert.get_not_before().get_datetime(),
        "not_after": cert.get_not_after().get_datetime(),
        "subject": cert.get_subject().as_text(),
        "cn": cert.get_subject().CN,
        "issuer": cert.get_issuer().as_text(),
        "fingerprint": cert.get_fingerprint(md='sha1'),
        "san": san,
        "serial": cert.get_serial_number(),
        "pub_key": "RSA " + str(cert.get_pubkey().size() * 8),
    }

