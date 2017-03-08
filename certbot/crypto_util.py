"""Certbot client crypto utility functions.

.. todo:: Make the transition to use PSS rather than PKCS1_v1_5 when the server
    is capable of handling the signatures.

"""
import logging
import os
import traceback

import OpenSSL
import pyrfc3339
import six
import zope.component

from acme import crypto_util as acme_crypto_util
from acme import jose

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

    logger.info("Generating key (%d bits): %s", key_size, key_path)

    return util.Key(key_path, key_pem)


def init_save_csr(privkey, names, path, csrname="csr-certbot.pem"):
    """Initialize a CSR with the given private key.

    :param privkey: Key to include in the CSR
    :type privkey: :class:`certbot.util.Key`

    :param set names: `str` names to include in the CSR

    :param str path: Certificate save directory.

    :returns: CSR
    :rtype: :class:`certbot.util.CSR`

    """
    config = zope.component.getUtility(interfaces.IConfig)

    csr_pem, csr_der = make_csr(privkey.pem, names,
        must_staple=config.must_staple)

    # Save CSR
    util.make_or_verify_dir(path, 0o755, os.geteuid(),
                               config.strict_permissions)
    csr_f, csr_filename = util.unique_file(
        os.path.join(path, csrname), 0o644, "wb")
    csr_f.write(csr_pem)
    csr_f.close()

    logger.info("Creating CSR: %s", csr_filename)

    return util.CSR(csr_filename, csr_der, "der")


# Lower level functions
def make_csr(key_str, domains, must_staple=False):
    """Generate a CSR.

    :param str key_str: PEM-encoded RSA key.
    :param list domains: Domains included in the certificate.

    .. todo:: Detect duplicates in `domains`? Using a set doesn't
              preserve order...

    :returns: new CSR in PEM and DER form containing all domains
    :rtype: tuple

    """
    assert domains, "Must provide one or more hostnames for the CSR."
    pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_str)
    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN = domains[0]
    # TODO: what to put into req.get_subject()?
    # TODO: put SAN if len(domains) > 1
    extensions = [
        OpenSSL.crypto.X509Extension(
            b"subjectAltName",
            critical=False,
            value=", ".join("DNS:%s" % d for d in domains).encode('ascii')
        )
    ]
    if must_staple:
        extensions.append(OpenSSL.crypto.X509Extension(
            b"1.3.6.1.5.5.7.1.24",
            critical=False,
            value=b"DER:30:03:02:01:05"))
    req.add_extensions(extensions)
    req.set_version(2)
    req.set_pubkey(pkey)
    req.sign(pkey, "sha256")
    return tuple(OpenSSL.crypto.dump_certificate_request(method, req)
                 for method in (OpenSSL.crypto.FILETYPE_PEM,
                                OpenSSL.crypto.FILETYPE_ASN1))


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

    :returns: (`OpenSSL.crypto.FILETYPE_PEM` or `OpenSSL.crypto.FILETYPE_ASN1`,
               util.CSR object representing the CSR,
               list of domains requested in the CSR)
    :rtype: tuple

    """
    for form, typ in (("der", OpenSSL.crypto.FILETYPE_ASN1,),
                      ("pem", OpenSSL.crypto.FILETYPE_PEM,),):
        try:
            domains = get_names_from_csr(data, typ)
        except OpenSSL.crypto.Error:
            logger.debug("CSR parse error (form=%s, typ=%s):", form, typ)
            logger.debug(traceback.format_exc())
            continue
        return typ, util.CSR(file=csrfile, data=data, form=form), domains
    raise errors.Error("Failed to parse CSR file: {0}".format(csrfile))


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


def get_sans_from_csr(csr, typ=OpenSSL.crypto.FILETYPE_PEM):
    """Get a list of Subject Alternative Names from a CSR.

    :param str csr: CSR (encoded).
    :param typ: `OpenSSL.crypto.FILETYPE_PEM` or `OpenSSL.crypto.FILETYPE_ASN1`

    :returns: A list of Subject Alternative Names.
    :rtype: list

    """
    return _get_sans_from_cert_or_req(
        csr, OpenSSL.crypto.load_certificate_request, typ)


def _get_names_from_cert_or_req(cert_or_req, load_func, typ):
    loaded_cert_or_req = _load_cert_or_req(cert_or_req, load_func, typ)
    common_name = loaded_cert_or_req.get_subject().CN
    # pylint: disable=protected-access
    sans = acme_crypto_util._pyopenssl_cert_or_req_san(loaded_cert_or_req)

    if common_name is None:
        return sans
    else:
        return [common_name] + [d for d in sans if d != common_name]


def get_names_from_cert(csr, typ=OpenSSL.crypto.FILETYPE_PEM):
    """Get a list of domains from a cert, including the CN if it is set.

    :param str cert: Certificate (encoded).
    :param typ: `OpenSSL.crypto.FILETYPE_PEM` or `OpenSSL.crypto.FILETYPE_ASN1`

    :returns: A list of domain names.
    :rtype: list

    """
    return _get_names_from_cert_or_req(
        csr, OpenSSL.crypto.load_certificate, typ)


def get_names_from_csr(csr, typ=OpenSSL.crypto.FILETYPE_PEM):
    """Get a list of domains from a CSR, including the CN if it is set.

    :param str csr: CSR (encoded).
    :param typ: `OpenSSL.crypto.FILETYPE_PEM` or `OpenSSL.crypto.FILETYPE_ASN1`

    :returns: A list of domain names.
    :rtype: list

    """
    return _get_names_from_cert_or_req(
        csr, OpenSSL.crypto.load_certificate_request, typ)


def dump_pyopenssl_chain(chain, filetype=OpenSSL.crypto.FILETYPE_PEM):
    """Dump certificate chain into a bundle.

    :param list chain: List of `OpenSSL.crypto.X509` (or wrapped in
        `acme.jose.ComparableX509`).

    """
    # XXX: returns empty string when no chain is available, which
    # shuts up RenewableCert, but might not be the best solution...

    def _dump_cert(cert):
        if isinstance(cert, jose.ComparableX509):
            # pylint: disable=protected-access
            cert = cert.wrapped
        return OpenSSL.crypto.dump_certificate(filetype, cert)

    # assumes that OpenSSL.crypto.dump_certificate includes ending
    # newline character
    return b"".join(_dump_cert(cert) for cert in chain)


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
