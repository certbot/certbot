import M2Crypto
import time, jose, binascii
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from M2Crypto import EVP, X509, ASN1


from letsencrypt.client import logger
from letsencrypt.client.CONFIG import NONCE_SIZE, RSA_KEY_SIZE


def b64_cert_to_pem(b64_der_cert):
    x = M2Crypto.X509.load_cert_der_string(jose.b64decode_url(b64_der_cert))
    return x.as_pem()

def create_sig(msg, key_file, signer_nonce = None, signer_nonce_len = NONCE_SIZE):
    # DOES prepend signer_nonce to message
    # TODO: Change this over to M2Crypto... PKey
    # Protect against crypto unicode errors... is this sufficient? Do I need to escape?
    msg = str(msg)
    key = RSA.importKey(open(key_file).read())
    if signer_nonce is None:
        signer_nonce = get_random_bytes(signer_nonce_len)
    h = SHA256.new(signer_nonce + msg)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)
    #print "signing:", signer_nonce + msg
    #print "signature:", signature
    n, e = key.n, key.e
    n_bytes = binascii.unhexlify(leading_zeros(hex(n)[2:].replace("L", "")))
    e_bytes = binascii.unhexlify(leading_zeros(hex(e)[2:].replace("L", "")))
    n_encoded = jose.b64encode_url(n_bytes)
    e_encoded = jose.b64encode_url(e_bytes)
    signer_nonce_encoded = jose.b64encode_url(signer_nonce)
    sig_encoded = jose.b64encode_url(signature)
    jwk = { "kty": "RSA", "n": n_encoded, "e": e_encoded }
    signature = { "nonce": signer_nonce_encoded, "alg": "RS256", "jwk": jwk, "sig": sig_encoded }
    # return json.dumps(signature)
    return (signature)

def leading_zeros(s):
    if len(s) % 2:
        return "0" + s
    return s

def sha256(m):
    return hashlib.sha256(m).hexdigest()

# based on M2Crypto unit test written by Toby Allsopp
def make_key(bits=RSA_KEY_SIZE):
    """
    Returns new RSA key in PEM form with specified bits
    """
    #Python Crypto module doesn't produce any stdout
    key = RSA.generate(bits)
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
    pk = EVP.PKey()
    pk.assign_rsa(rsa_key)

    x = X509.Request()
    x.set_pubkey(pk)
    name = x.get_subject()
    name.C = "US"
    name.ST = "Michigan"
    name.L = "Ann Arbor"
    name.O = "EFF"
    name.OU = "University of Michigan"
    name.CN = domains[0]

    extstack = X509.X509_Extension_Stack()
    ext = X509.new_extension('subjectAltName', ", ".join(["DNS:%s" % d for d in domains]))

    extstack.push(ext)
    x.add_extensions(extstack)
    x.sign(pk,'sha256')
    assert x.verify(pk)
    pk2 = x.get_pubkey()
    assert x.verify(pk2)
    return x.as_pem(), x.as_der()

def make_ss_cert(key_file, domains):
    """
    Returns new self-signed cert in PEM form using key_file containing all domains
    """
    assert domains, "Must provide one or more hostnames for the CSR."
    rsa_key = M2Crypto.RSA.load_key(key_file)
    pk = EVP.PKey()
    pk.assign_rsa(rsa_key)

    x = X509.X509()
    x.set_pubkey(pk)
    x.set_serial_number(1337)
    x.set_version(2)

    t = long(time.time())
    current = ASN1.ASN1_UTCTIME()
    current.set_time(t)
    expire = ASN1.ASN1_UTCTIME()
    expire.set_time((7 * 24 * 60 * 60) + t)
    x.set_not_before(current)
    x.set_not_after(expire)

    name = x.get_subject()
    name.C = "US"
    name.ST = "Michigan"
    name.L = "Ann Arbor"
    name.O = "University of Michigan and the EFF"
    name.CN = domains[0]
    x.set_issuer(x.get_subject())

    x.add_ext(X509.new_extension('basicConstraints', 'CA:FALSE'))
    #x.add_ext(X509.new_extension('extendedKeyUsage', 'TLS Web Server Authentication'))
    x.add_ext(X509.new_extension('subjectAltName', ", ".join(["DNS:%s" % d for d in domains])))

    x.sign(pk, 'sha256')
    assert x.verify(pk)
    assert x.verify()
    #print check_purpose(,0
    return x.as_pem()

def get_cert_info(filename):
    d = {}
    # M2Crypto Library only supports RSA right now
    x = M2Crypto.X509.load_cert(filename)
    d["not_before"] = x.get_not_before().get_datetime()
    d["not_after"] = x.get_not_after().get_datetime()
    d["subject"] = x.get_subject().as_text()
    d["cn"] = x.get_subject().CN
    d["issuer"] = x.get_issuer().as_text()
    d["fingerprint"] = x.get_fingerprint(md='sha1')
    try:
        d["san"] = x.get_ext("subjectAltName").get_value()
    except:
        d["san"] = ""
    
    d["serial"] = x.get_serial_number()
    d["pub_key"] = "RSA " + str(x.get_pubkey().size() * 8)
    return d
