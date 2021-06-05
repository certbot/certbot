"""Certbot client crypto utility functions.

.. todo:: Make the transition to use PSS rather than PKCS1_v1_5 when the server
    is capable of handling the signatures.

"""
import hashlib
import logging
import re
import warnings

from typing import List, Set
# See https://github.com/pyca/cryptography/issues/4275
from cryptography import x509  # type: ignore
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from OpenSSL import crypto
from OpenSSL import SSL  # type: ignore
import pyrfc3339
import zope.component

from acme import crypto_util as acme_crypto_util
from certbot import errors
from certbot import interfaces
from certbot import util
from certbot.compat import os

logger = logging.getLogger(__name__)


# High level functions

def generate_key(key_size: int, key_dir: str, key_type: str = "rsa",
                 elliptic_curve: str = "secp256r1", keyname: str = "key-certbot.pem",
                 strict_permissions: bool = True) -> util.Key:
    """Initializes and saves a privkey.

    Inits key and saves it in PEM format on the filesystem.

    .. note:: keyname is the attempted filename, it may be different if a file
        already exists at the path.

    :param int key_size: key size in bits if key size is rsa.
    :param str key_dir: Key save directory.
    :param str key_type: Key Type [rsa, ecdsa]
    :param str elliptic_curve: Name of the elliptic curve if key type is ecdsa.
    :param str keyname: Filename of key
    :param bool strict_permissions: If true and key_dir exists, an exception is raised if
        the directory doesn't have 0700 permissions or isn't owned by the current user.

    :returns: Key
    :rtype: :class:`certbot.util.Key`

    :raises ValueError: If unable to generate the key given key_size.

    """
    try:
        key_pem = make_key(
            bits=key_size, elliptic_curve=elliptic_curve or "secp256r1", key_type=key_type,
        )
    except ValueError as err:
        logger.debug("", exc_info=True)
        logger.error("Encountered error while making key: %s", str(err))
        raise err

    # Save file
    util.make_or_verify_dir(key_dir, 0o700, strict_permissions)
    key_f, key_path = util.unique_file(
        os.path.join(key_dir, keyname), 0o600, "wb")
    with key_f:
        key_f.write(key_pem)
    if key_type == 'rsa':
        logger.debug("Generating RSA key (%d bits): %s", key_size, key_path)
    else:
        logger.debug("Generating ECDSA key (%d bits): %s", key_size, key_path)

    return util.Key(key_path, key_pem)


# TODO: Remove this call once zope dependencies are removed from Certbot.
def init_save_key(key_size, key_dir, key_type="rsa", elliptic_curve="secp256r1",
                  keyname="key-certbot.pem"):
    """Initializes and saves a privkey.

    Inits key and saves it in PEM format on the filesystem.

    .. note:: keyname is the attempted filename, it may be different if a file
        already exists at the path.

    .. deprecated:: 1.16.0
       Use :func:`generate_key` instead.

    :param int key_size: key size in bits if key size is rsa.
    :param str key_dir: Key save directory.
    :param str key_type: Key Type [rsa, ecdsa]
    :param str elliptic_curve: Name of the elliptic curve if key type is ecdsa.
    :param str keyname: Filename of key

    :returns: Key
    :rtype: :class:`certbot.util.Key`

    :raises ValueError: If unable to generate the key given key_size.

    """
    warnings.warn("certbot.crypto_util.init_save_key is deprecated, please use "
                  "certbot.crypto_util.generate_key instead.", DeprecationWarning)

    config = zope.component.getUtility(interfaces.IConfig)

    return generate_key(key_size, key_dir, key_type=key_type, elliptic_curve=elliptic_curve,
                        keyname=keyname, strict_permissions=config.strict_permissions)


def generate_csr(privkey: util.Key, names: Set[str], path: str,
                 must_staple: bool = False, strict_permissions: bool = True) -> util.CSR:
    """Initialize a CSR with the given private key.

    :param privkey: Key to include in the CSR
    :type privkey: :class:`certbot.util.Key`
    :param set names: `str` names to include in the CSR
    :param str path: Certificate save directory.
    :param bool must_staple: If true, include the TLS Feature extension "OCSP Must Staple"
    :param bool strict_permissions: If true and path exists, an exception is raised if
        the directory doesn't have 0755 permissions or isn't owned by the current user.

    :returns: CSR
    :rtype: :class:`certbot.util.CSR`

    """
    csr_pem = acme_crypto_util.make_csr(
        privkey.pem, names, must_staple=must_staple)

    # Save CSR
    util.make_or_verify_dir(path, 0o755, strict_permissions)
    csr_f, csr_filename = util.unique_file(
        os.path.join(path, "csr-certbot.pem"), 0o644, "wb")
    with csr_f:
        csr_f.write(csr_pem)
    logger.debug("Creating CSR: %s", csr_filename)

    return util.CSR(csr_filename, csr_pem, "pem")


# TODO: Remove this call once zope dependencies are removed from Certbot.
def init_save_csr(privkey, names, path):
    """Initialize a CSR with the given private key.

    .. deprecated:: 1.16.0
       Use :func:`generate_csr` instead.

    :param privkey: Key to include in the CSR
    :type privkey: :class:`certbot.util.Key`

    :param set names: `str` names to include in the CSR

    :param str path: Certificate save directory.

    :returns: CSR
    :rtype: :class:`certbot.util.CSR`

    """
    warnings.warn("certbot.crypto_util.init_save_csr is deprecated, please use "
                  "certbot.crypto_util.generate_csr instead.", DeprecationWarning)

    config = zope.component.getUtility(interfaces.IConfig)

    return generate_csr(privkey, names, path, must_staple=config.must_staple,
                        strict_permissions=config.strict_permissions)


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
        req = crypto.load_certificate_request(
            crypto.FILETYPE_PEM, csr)
        return req.verify(req.get_pubkey())
    except crypto.Error:
        logger.debug("", exc_info=True)
        return False


def csr_matches_pubkey(csr, privkey):
    """Does private key correspond to the subject public key in the CSR?

    :param str csr: CSR in PEM.
    :param str privkey: Private key file contents (PEM)

    :returns: Correspondence of private key to CSR subject public key.
    :rtype: bool

    """
    req = crypto.load_certificate_request(
        crypto.FILETYPE_PEM, csr)
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, privkey)
    try:
        return req.verify(pkey)
    except crypto.Error:
        logger.debug("", exc_info=True)
        return False


def import_csr_file(csrfile, data):
    """Import a CSR file, which can be either PEM or DER.

    :param str csrfile: CSR filename
    :param str data: contents of the CSR file

    :returns: (`crypto.FILETYPE_PEM`,
               util.CSR object representing the CSR,
               list of domains requested in the CSR)
    :rtype: tuple

    """
    PEM = crypto.FILETYPE_PEM
    load = crypto.load_certificate_request
    try:
        # Try to parse as DER first, then fall back to PEM.
        csr = load(crypto.FILETYPE_ASN1, data)
    except crypto.Error:
        try:
            csr = load(PEM, data)
        except crypto.Error:
            raise errors.Error("Failed to parse CSR file: {0}".format(csrfile))

    domains = _get_names_from_loaded_cert_or_req(csr)
    # Internally we always use PEM, so re-encode as PEM before returning.
    data_pem = crypto.dump_certificate_request(PEM, csr)
    return PEM, util.CSR(file=csrfile, data=data_pem, form="pem"), domains


def make_key(bits=1024, key_type="rsa", elliptic_curve=None):
    """Generate PEM encoded RSA|EC key.

    :param int bits: Number of bits if key_type=rsa. At least 1024 for RSA.

    :param str ec_curve: The elliptic curve to use.

    :returns: new RSA or ECDSA key in PEM form with specified number of bits
              or of type ec_curve when key_type ecdsa is used.
    :rtype: str
    """
    if key_type == 'rsa':
        if bits < 1024:
            raise errors.Error("Unsupported RSA key length: {}".format(bits))

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, bits)
    elif key_type == 'ecdsa':
        try:
            name = elliptic_curve.upper()
            if name in ('SECP256R1', 'SECP384R1', 'SECP521R1'):
                _key = ec.generate_private_key(
                    curve=getattr(ec, elliptic_curve.upper(), None)(),
                    backend=default_backend()
                )
            else:
                raise errors.Error("Unsupported elliptic curve: {}".format(elliptic_curve))
        except TypeError:
            raise errors.Error("Unsupported elliptic curve: {}".format(elliptic_curve))
        except UnsupportedAlgorithm as e:
            raise e from errors.Error(str(e))
        _key_pem = _key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, _key_pem)
    else:
        raise errors.Error("Invalid key_type specified: {}.  Use [rsa|ecdsa]".format(key_type))
    return crypto.dump_privatekey(crypto.FILETYPE_PEM, key)


def valid_privkey(privkey):
    """Is valid RSA private key?

    :param str privkey: Private key file contents in PEM

    :returns: Validity of private key.
    :rtype: bool

    """
    try:
        return crypto.load_privatekey(
            crypto.FILETYPE_PEM, privkey).check()
    except (TypeError, crypto.Error):
        return False


def verify_renewable_cert(renewable_cert):
    """For checking that your certs were not corrupted on disk.

    Several things are checked:
        1. Signature verification for the cert.
        2. That fullchain matches cert and chain when concatenated.
        3. Check that the private key matches the certificate.

    :param renewable_cert: cert to verify
    :type renewable_cert: certbot.interfaces.RenewableCert

    :raises errors.Error: If verification fails.
    """
    verify_renewable_cert_sig(renewable_cert)
    verify_fullchain(renewable_cert)
    verify_cert_matches_priv_key(renewable_cert.cert_path, renewable_cert.key_path)


def verify_renewable_cert_sig(renewable_cert):
    """Verifies the signature of a RenewableCert object.

    :param renewable_cert: cert to verify
    :type renewable_cert: certbot.interfaces.RenewableCert

    :raises errors.Error: If signature verification fails.
    """
    try:
        with open(renewable_cert.chain_path, 'rb') as chain_file:
            chain = x509.load_pem_x509_certificate(chain_file.read(), default_backend())
        with open(renewable_cert.cert_path, 'rb') as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        pk = chain.public_key()
        with warnings.catch_warnings():
            verify_signed_payload(pk, cert.signature, cert.tbs_certificate_bytes,
                                  cert.signature_hash_algorithm)
    except (IOError, ValueError, InvalidSignature) as e:
        error_str = "verifying the signature of the certificate located at {0} has failed. \
                Details: {1}".format(renewable_cert.cert_path, e)
        logger.exception(error_str)
        raise errors.Error(error_str)


def verify_signed_payload(public_key, signature, payload, signature_hash_algorithm):
    """Check the signature of a payload.

    :param RSAPublicKey/EllipticCurvePublicKey public_key: the public_key to check signature
    :param bytes signature: the signature bytes
    :param bytes payload: the payload bytes
    :param cryptography.hazmat.primitives.hashes.HashAlgorithm \
           signature_hash_algorithm: algorithm used to hash the payload

    :raises InvalidSignature: If signature verification fails.
    :raises errors.Error: If public key type is not supported
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if isinstance(public_key, RSAPublicKey):
            verifier = public_key.verifier(
                signature, PKCS1v15(), signature_hash_algorithm
            )
            verifier.update(payload)
            verifier.verify()
        elif isinstance(public_key, EllipticCurvePublicKey):
            verifier = public_key.verifier(
                signature, ECDSA(signature_hash_algorithm)
            )
            verifier.update(payload)
            verifier.verify()
        else:
            raise errors.Error("Unsupported public key type")


def verify_cert_matches_priv_key(cert_path, key_path):
    """ Verifies that the private key and cert match.

    :param str cert_path: path to a cert in PEM format
    :param str key_path: path to a private key file

    :raises errors.Error: If they don't match.
    """
    try:
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.use_certificate_file(cert_path)
        context.use_privatekey_file(key_path)
        context.check_privatekey()
    except (IOError, SSL.Error) as e:
        error_str = "verifying the certificate located at {0} matches the \
                private key located at {1} has failed. \
                Details: {2}".format(cert_path,
                        key_path, e)
        logger.exception(error_str)
        raise errors.Error(error_str)


def verify_fullchain(renewable_cert):
    """ Verifies that fullchain is indeed cert concatenated with chain.

    :param renewable_cert: cert to verify
    :type renewable_cert: certbot.interfaces.RenewableCert

    :raises errors.Error: If cert and chain do not combine to fullchain.
    """
    try:
        with open(renewable_cert.chain_path) as chain_file:
            chain = chain_file.read()
        with open(renewable_cert.cert_path) as cert_file:
            cert = cert_file.read()
        with open(renewable_cert.fullchain_path) as fullchain_file:
            fullchain = fullchain_file.read()
        if (cert + chain) != fullchain:
            error_str = "fullchain does not match cert + chain for {0}!"
            error_str = error_str.format(renewable_cert.lineagename)
            raise errors.Error(error_str)
    except IOError as e:
        error_str = "reading one of cert, chain, or fullchain has failed: {0}".format(e)
        logger.exception(error_str)
        raise errors.Error(error_str)
    except errors.Error as e:
        raise e


def pyopenssl_load_certificate(data):
    """Load PEM/DER certificate.

    :raises errors.Error:

    """

    openssl_errors = []

    for file_type in (crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1):
        try:
            return crypto.load_certificate(file_type, data), file_type
        except crypto.Error as error:  # TODO: other errors?
            openssl_errors.append(error)
    raise errors.Error("Unable to load: {0}".format(",".join(
        str(error) for error in openssl_errors)))


def _load_cert_or_req(cert_or_req_str, load_func,
                      typ=crypto.FILETYPE_PEM):
    try:
        return load_func(typ, cert_or_req_str)
    except crypto.Error as err:
        logger.debug("", exc_info=True)
        logger.error("Encountered error while loading certificate or csr: %s", str(err))
        raise


def _get_sans_from_cert_or_req(cert_or_req_str, load_func,
                               typ=crypto.FILETYPE_PEM):
    # pylint: disable=protected-access
    return acme_crypto_util._pyopenssl_cert_or_req_san(_load_cert_or_req(
        cert_or_req_str, load_func, typ))


def get_sans_from_cert(cert, typ=crypto.FILETYPE_PEM):
    """Get a list of Subject Alternative Names from a certificate.

    :param str cert: Certificate (encoded).
    :param typ: `crypto.FILETYPE_PEM` or `crypto.FILETYPE_ASN1`

    :returns: A list of Subject Alternative Names.
    :rtype: list

    """
    return _get_sans_from_cert_or_req(
        cert, crypto.load_certificate, typ)


def _get_names_from_cert_or_req(cert_or_req, load_func, typ):
    loaded_cert_or_req = _load_cert_or_req(cert_or_req, load_func, typ)
    return _get_names_from_loaded_cert_or_req(loaded_cert_or_req)


def _get_names_from_loaded_cert_or_req(loaded_cert_or_req):
    # pylint: disable=protected-access
    return acme_crypto_util._pyopenssl_cert_or_req_all_names(loaded_cert_or_req)


def get_names_from_cert(csr, typ=crypto.FILETYPE_PEM):
    """Get a list of domains from a cert, including the CN if it is set.

    :param str cert: Certificate (encoded).
    :param typ: `crypto.FILETYPE_PEM` or `crypto.FILETYPE_ASN1`

    :returns: A list of domain names.
    :rtype: list

    """
    return _get_names_from_cert_or_req(
        csr, crypto.load_certificate, typ)


def get_names_from_req(csr: str, typ: int = crypto.FILETYPE_PEM) -> List[str]:
    """Get a list of domains from a CSR, including the CN if it is set.

    :param str cert: CSR (encoded).
    :param typ: `crypto.FILETYPE_PEM` or `crypto.FILETYPE_ASN1`
    :returns: A list of domain names.
    :rtype: list

    """
    return _get_names_from_cert_or_req(csr, crypto.load_certificate_request, typ)


def dump_pyopenssl_chain(chain, filetype=crypto.FILETYPE_PEM):
    """Dump certificate chain into a bundle.

    :param list chain: List of `crypto.X509` (or wrapped in
        :class:`josepy.util.ComparableX509`).

    """
    # XXX: returns empty string when no chain is available, which
    # shuts up RenewableCert, but might not be the best solution...
    return acme_crypto_util.dump_pyopenssl_chain(chain, filetype)


def notBefore(cert_path):
    """When does the cert at cert_path start being valid?

    :param str cert_path: path to a cert in PEM format

    :returns: the notBefore value from the cert at cert_path
    :rtype: :class:`datetime.datetime`

    """
    return _notAfterBefore(cert_path, crypto.X509.get_notBefore)


def notAfter(cert_path):
    """When does the cert at cert_path stop being valid?

    :param str cert_path: path to a cert in PEM format

    :returns: the notAfter value from the cert at cert_path
    :rtype: :class:`datetime.datetime`

    """
    return _notAfterBefore(cert_path, crypto.X509.get_notAfter)


def _notAfterBefore(cert_path, method):
    """Internal helper function for finding notbefore/notafter.

    :param str cert_path: path to a cert in PEM format
    :param function method: one of ``crypto.X509.get_notBefore``
        or ``crypto.X509.get_notAfter``

    :returns: the notBefore or notAfter value from the cert at cert_path
    :rtype: :class:`datetime.datetime`

    """
    # pylint: disable=redefined-outer-name
    with open(cert_path, "rb") as f:
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    # pyopenssl always returns bytes
    timestamp = method(x509)
    reformatted_timestamp = [timestamp[0:4], b"-", timestamp[4:6], b"-",
                             timestamp[6:8], b"T", timestamp[8:10], b":",
                             timestamp[10:12], b":", timestamp[12:]]
    # pyrfc3339 always uses the type `str`
    timestamp_bytes = b"".join(reformatted_timestamp)
    timestamp_str = timestamp_bytes.decode('ascii')
    return pyrfc3339.parse(timestamp_str)


def sha256sum(filename):
    """Compute a sha256sum of a file.

    NB: In given file, platform specific newlines characters will be converted
    into their equivalent unicode counterparts before calculating the hash.

    :param str filename: path to the file whose hash will be computed

    :returns: sha256 digest of the file in hexadecimal
    :rtype: str
    """
    sha256 = hashlib.sha256()
    with open(filename, 'r') as file_d:
        sha256.update(file_d.read().encode('UTF-8'))
    return sha256.hexdigest()

# Finds one CERTIFICATE stricttextualmsg according to rfc7468#section-3.
# Does not validate the base64text - use crypto.load_certificate.
CERT_PEM_REGEX = re.compile(
    b"""-----BEGIN CERTIFICATE-----\r?
.+?\r?
-----END CERTIFICATE-----\r?
""",
    re.DOTALL # DOTALL (/s) because the base64text may include newlines
)


def cert_and_chain_from_fullchain(fullchain_pem):
    """Split fullchain_pem into cert_pem and chain_pem

    :param str fullchain_pem: concatenated cert + chain

    :returns: tuple of string cert_pem and chain_pem
    :rtype: tuple

    :raises errors.Error: If there are less than 2 certificates in the chain.

    """
    # First pass: find the boundary of each certificate in the chain.
    # TODO: This will silently skip over any "explanatory text" in between boundaries,
    # which is prohibited by RFC8555.
    certs = CERT_PEM_REGEX.findall(fullchain_pem.encode())
    if len(certs) < 2:
        raise errors.Error("failed to parse fullchain into cert and chain: " +
                           "less than 2 certificates in chain")

    # Second pass: for each certificate found, parse it using OpenSSL and re-encode it,
    # with the effect of normalizing any encoding variations (e.g. CRLF, whitespace).
    certs_normalized = [crypto.dump_certificate(crypto.FILETYPE_PEM,
        crypto.load_certificate(crypto.FILETYPE_PEM, cert)).decode() for cert in certs]

    # Since each normalized cert has a newline suffix, no extra newlines are required.
    return (certs_normalized[0], "".join(certs_normalized[1:]))


def get_serial_from_cert(cert_path):
    """Retrieve the serial number of a certificate from certificate path

    :param str cert_path: path to a cert in PEM format

    :returns: serial number of the certificate
    :rtype: int
    """
    # pylint: disable=redefined-outer-name
    with open(cert_path, "rb") as f:
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    return x509.get_serial_number()


def find_chain_with_issuer(fullchains, issuer_cn, warn_on_no_match=False):
    """Chooses the first certificate chain from fullchains whose topmost
    intermediate has an Issuer Common Name matching issuer_cn (in other words
    the first chain which chains to a root whose name matches issuer_cn).

    :param fullchains: The list of fullchains in PEM chain format.
    :type fullchains: `list` of `str`
    :param `str` issuer_cn: The exact Subject Common Name to match against any
        issuer in the certificate chain.

    :returns: The best-matching fullchain, PEM-encoded, or the first if none match.
    :rtype: `str`
    """
    for chain in fullchains:
        certs = CERT_PEM_REGEX.findall(chain.encode())
        top_cert = x509.load_pem_x509_certificate(certs[-1], default_backend())
        top_issuer_cn = top_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if top_issuer_cn and top_issuer_cn[0].value == issuer_cn:
            return chain

    # Nothing matched, return whatever was first in the list.
    if warn_on_no_match:
        logger.warning("Certbot has been configured to prefer certificate chains with "
                    "issuer '%s', but no chain from the CA matched this issuer. Using "
                    "the default certificate chain instead.", issuer_cn)
    return fullchains[0]
