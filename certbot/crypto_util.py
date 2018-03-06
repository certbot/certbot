"""Certbot client crypto utility functions.

.. todo:: Make the transition to use PSS rather than PKCS1_v1_5 when the server
    is capable of handling the signatures.

"""
import hashlib
import logging
import os

import OpenSSL
import pyrfc3339
import six
import zope.component
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from acme import crypto_util as acme_crypto_util

from certbot import errors
from certbot import interfaces
from certbot import util


logger = logging.getLogger(__name__)


# High level functions
def init_save_key(key_size, key_dir, keyname="key-certbot.pem"):
    """Initializes and saves a privkey.

    Inits key and saves it in PEM format on the filesystem.

    .. note:: keyname is the attempted filename, it may be different if a file
        already exists at the path.

    :param int key_size: RSA key size in bits
    :param str key_dir: Key save directory.
    :param str keyname: Filename of key

    :returns: Key
    :rtype: :class:`certbot.util.Key`

    :raises ValueError: If unable to generate the key given key_size.

    """
    try:
        key_pem = make_key(key_size)
    except ValueError as err:
        logger.exception(err)
        raise err

    config = zope.component.getUtility(interfaces.IConfig)
    # Save file
    util.make_or_verify_dir(key_dir, 0o700, os.geteuid(),
                            config.strict_permissions)
    key_f, key_path = util.unique_file(
        os.path.join(key_dir, keyname), 0o600, "wb")
    with key_f:
        key_f.write(key_pem)
    logger.debug("Generating key (%d bits): %s", key_size, key_path)

    return util.Key(key_path, key_pem)


def init_save_csr(privkey, names, path):
    """Initialize a CSR with the given private key.

    :param privkey: Key to include in the CSR
    :type privkey: :class:`certbot.util.Key`

    :param set names: `str` names to include in the CSR

    :param str path: Certificate save directory.

    :returns: CSR
    :rtype: :class:`certbot.util.CSR`

    """
    config = zope.component.getUtility(interfaces.IConfig)

    csr_pem = acme_crypto_util.make_csr(
        privkey.pem, names, must_staple=config.must_staple)

    # Save CSR
    util.make_or_verify_dir(path, 0o755, os.geteuid(),
                               config.strict_permissions)
    csr_f, csr_filename = util.unique_file(
        os.path.join(path, "csr-certbot.pem"), 0o644, "wb")
    with csr_f:
        csr_f.write(csr_pem)
    logger.debug("Creating CSR: %s", csr_filename)

    return util.CSR(csr_filename, csr_pem, "pem")


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
        req = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, csr)
        return req.verify(req.get_pubkey())
    except OpenSSL.crypto.Error as error:
        logger.debug(error, exc_info=True)
        return False


def csr_matches_pubkey(csr, privkey):
    """Does private key correspond to the subject public key in the CSR?

    :param str csr: CSR in PEM.
    :param str privkey: Private key file contents (PEM)

    :returns: Correspondence of private key to CSR subject public key.
    :rtype: bool

    """
    req = OpenSSL.crypto.load_certificate_request(
        OpenSSL.crypto.FILETYPE_PEM, csr)
    pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privkey)
    try:
        return req.verify(pkey)
    except OpenSSL.crypto.Error as error:
        logger.debug(error, exc_info=True)
        return False


def import_csr_file(csrfile, data):
    """Import a CSR file, which can be either PEM or DER.

    :param str csrfile: CSR filename
    :param str data: contents of the CSR file

    :returns: (`OpenSSL.crypto.FILETYPE_PEM`,
               util.CSR object representing the CSR,
               list of domains requested in the CSR)
    :rtype: tuple

    """
    PEM = OpenSSL.crypto.FILETYPE_PEM
    load = OpenSSL.crypto.load_certificate_request
    try:
        # Try to parse as DER first, then fall back to PEM.
        csr = load(OpenSSL.crypto.FILETYPE_ASN1, data)
    except OpenSSL.crypto.Error:
        try:
            csr = load(PEM, data)
        except OpenSSL.crypto.Error:
            raise errors.Error("Failed to parse CSR file: {0}".format(csrfile))

    domains = _get_names_from_loaded_cert_or_req(csr)
    # Internally we always use PEM, so re-encode as PEM before returning.
    data_pem = OpenSSL.crypto.dump_certificate_request(PEM, csr)
    return PEM, util.CSR(file=csrfile, data=data_pem, form="pem"), domains


def make_key(bits):
    """Generate PEM encoded RSA key.

    :param int bits: Number of bits, at least 1024.

    :returns: new RSA key in PEM form with specified number of bits
    :rtype: str

    """
    assert bits >= 1024  # XXX
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, bits)
    return OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)


def valid_privkey(privkey):
    """Is valid RSA private key?

    :param str privkey: Private key file contents in PEM

    :returns: Validity of private key.
    :rtype: bool

    """
    try:
        return OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, privkey).check()
    except (TypeError, OpenSSL.crypto.Error):
        return False


def verify_renewable_cert(renewable_cert):
    """For checking that your certs were not corrupted on disk.

    Several things are checked:
        1. Signature verification for the cert.
        2. That fullchain matches cert and chain when concatenated.
        3. Check that the private key matches the certificate.

    :param `.storage.RenewableCert` renewable_cert: cert to verify

    :raises errors.Error: If verification fails.
    """
    verify_renewable_cert_sig(renewable_cert)
    verify_fullchain(renewable_cert)
    verify_cert_matches_priv_key(renewable_cert.cert, renewable_cert.privkey)


def verify_renewable_cert_sig(renewable_cert):
    """ Verifies the signature of a `.storage.RenewableCert` object.

    :param `.storage.RenewableCert` renewable_cert: cert to verify

    :raises errors.Error: If signature verification fails.
    """
    try:
        with open(renewable_cert.chain, 'rb') as chain:
            chain, _ = pyopenssl_load_certificate(chain.read())
        with open(renewable_cert.cert, 'rb') as cert:
            cert = x509.load_pem_x509_certificate(cert.read(), default_backend())
        hash_name = cert.signature_hash_algorithm.name
        OpenSSL.crypto.verify(chain, cert.signature, cert.tbs_certificate_bytes, hash_name)
    except (IOError, ValueError, OpenSSL.crypto.Error) as e:
        error_str = "verifying the signature of the cert located at {0} has failed. \
                Details: {1}".format(renewable_cert.cert, e)
        logger.exception(error_str)
        raise errors.Error(error_str)


def verify_cert_matches_priv_key(cert_path, key_path):
    """ Verifies that the private key and cert match.

    :param str cert_path: path to a cert in PEM format
    :param str key_path: path to a private key file

    :raises errors.Error: If they don't match.
    """
    try:
        context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        context.use_certificate_file(cert_path)
        context.use_privatekey_file(key_path)
        context.check_privatekey()
    except (IOError, OpenSSL.SSL.Error) as e:
        error_str = "verifying the cert located at {0} matches the \
                private key located at {1} has failed. \
                Details: {2}".format(cert_path,
                        key_path, e)
        logger.exception(error_str)
        raise errors.Error(error_str)


def verify_fullchain(renewable_cert):
    """ Verifies that fullchain is indeed cert concatenated with chain.

    :param `.storage.RenewableCert` renewable_cert: cert to verify

    :raises errors.Error: If cert and chain do not combine to fullchain.
    """
    try:
        with open(renewable_cert.chain) as chain:
            chain = chain.read()
        with open(renewable_cert.cert) as cert:
            cert = cert.read()
        with open(renewable_cert.fullchain) as fullchain:
            fullchain = fullchain.read()
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

    for file_type in (OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1):
        try:
            return OpenSSL.crypto.load_certificate(file_type, data), file_type
        except OpenSSL.crypto.Error as error:  # TODO: other errors?
            openssl_errors.append(error)
    raise errors.Error("Unable to load: {0}".format(",".join(
        str(error) for error in openssl_errors)))


def _load_cert_or_req(cert_or_req_str, load_func,
                      typ=OpenSSL.crypto.FILETYPE_PEM):
    try:
        return load_func(typ, cert_or_req_str)
    except OpenSSL.crypto.Error as error:
        logger.exception(error)
        raise


def _get_sans_from_cert_or_req(cert_or_req_str, load_func,
                               typ=OpenSSL.crypto.FILETYPE_PEM):
    # pylint: disable=protected-access
    return acme_crypto_util._pyopenssl_cert_or_req_san(_load_cert_or_req(
        cert_or_req_str, load_func, typ))


def get_sans_from_cert(cert, typ=OpenSSL.crypto.FILETYPE_PEM):
    """Get a list of Subject Alternative Names from a certificate.

    :param str cert: Certificate (encoded).
    :param typ: `OpenSSL.crypto.FILETYPE_PEM` or `OpenSSL.crypto.FILETYPE_ASN1`

    :returns: A list of Subject Alternative Names.
    :rtype: list

    """
    return _get_sans_from_cert_or_req(
        cert, OpenSSL.crypto.load_certificate, typ)


def _get_names_from_cert_or_req(cert_or_req, load_func, typ):
    loaded_cert_or_req = _load_cert_or_req(cert_or_req, load_func, typ)
    return _get_names_from_loaded_cert_or_req(loaded_cert_or_req)


def _get_names_from_loaded_cert_or_req(loaded_cert_or_req):
    # pylint: disable=protected-access
    return acme_crypto_util._pyopenssl_cert_or_req_all_names(loaded_cert_or_req)


def get_names_from_cert(csr, typ=OpenSSL.crypto.FILETYPE_PEM):
    """Get a list of domains from a cert, including the CN if it is set.

    :param str cert: Certificate (encoded).
    :param typ: `OpenSSL.crypto.FILETYPE_PEM` or `OpenSSL.crypto.FILETYPE_ASN1`

    :returns: A list of domain names.
    :rtype: list

    """
    return _get_names_from_cert_or_req(
        csr, OpenSSL.crypto.load_certificate, typ)


def dump_pyopenssl_chain(chain, filetype=OpenSSL.crypto.FILETYPE_PEM):
    """Dump certificate chain into a bundle.

    :param list chain: List of `OpenSSL.crypto.X509` (or wrapped in
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
    return _notAfterBefore(cert_path, OpenSSL.crypto.X509.get_notBefore)


def notAfter(cert_path):
    """When does the cert at cert_path stop being valid?

    :param str cert_path: path to a cert in PEM format

    :returns: the notAfter value from the cert at cert_path
    :rtype: :class:`datetime.datetime`

    """
    return _notAfterBefore(cert_path, OpenSSL.crypto.X509.get_notAfter)


def _notAfterBefore(cert_path, method):
    """Internal helper function for finding notbefore/notafter.

    :param str cert_path: path to a cert in PEM format
    :param function method: one of ``OpenSSL.crypto.X509.get_notBefore``
        or ``OpenSSL.crypto.X509.get_notAfter``

    :returns: the notBefore or notAfter value from the cert at cert_path
    :rtype: :class:`datetime.datetime`

    """
    # pylint: disable=redefined-outer-name
    with open(cert_path) as f:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                               f.read())
    # pyopenssl always returns bytes
    timestamp = method(x509)
    reformatted_timestamp = [timestamp[0:4], b"-", timestamp[4:6], b"-",
                             timestamp[6:8], b"T", timestamp[8:10], b":",
                             timestamp[10:12], b":", timestamp[12:]]
    timestamp_str = b"".join(reformatted_timestamp)
    # pyrfc3339 uses "native" strings. That is, bytes on Python 2 and unicode
    # on Python 3
    if six.PY3:
        timestamp_str = timestamp_str.decode('ascii')
    return pyrfc3339.parse(timestamp_str)


def sha256sum(filename):
    """Compute a sha256sum of a file.

    :param str filename: path to the file whose hash will be computed

    :returns: sha256 digest of the file in hexadecimal
    :rtype: str
    """
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        sha256.update(f.read())
    return sha256.hexdigest()

def cert_and_chain_from_fullchain(fullchain_pem):
    """Split fullchain_pem into cert_pem and chain_pem

    :param str fullchain_pem: concatenated cert + chain

    :returns: tuple of string cert_pem and chain_pem
    :rtype: tuple

    """
    cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
        OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fullchain_pem)).decode()
    chain = fullchain_pem[len(cert):]
    return (cert, chain)
