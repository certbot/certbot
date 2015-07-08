"""Let's Encrypt client crypto utility functions.

.. todo:: Make the transition to use PSS rather than PKCS1_v1_5 when the server
    is capable of handling the signatures.

"""
import datetime
import logging
import os

import OpenSSL

from letsencrypt import errors
from letsencrypt import le_util


logger = logging.getLogger(__name__)


# High level functions
def init_save_key(key_size, key_dir, keyname="key-letsencrypt.pem"):
    """Initializes and saves a privkey.

    Inits key and saves it in PEM format on the filesystem.

    .. note:: keyname is the attempted filename, it may be different if a file
        already exists at the path.

    :param int key_size: RSA key size in bits
    :param str key_dir: Key save directory.
    :param str keyname: Filename of key

    :returns: Key
    :rtype: :class:`letsencrypt.le_util.Key`

    :raises ValueError: If unable to generate the key given key_size.

    """
    try:
        key_pem = make_key(key_size)
    except ValueError as err:
        logger.exception(err)
        raise err

    # Save file
    le_util.make_or_verify_dir(key_dir, 0o700, os.geteuid())
    key_f, key_path = le_util.unique_file(
        os.path.join(key_dir, keyname), 0o600)
    key_f.write(key_pem)
    key_f.close()

    logger.info("Generating key (%d bits): %s", key_size, key_path)

    return le_util.Key(key_path, key_pem)


def init_save_csr(privkey, names, path, csrname="csr-letsencrypt.pem"):
    """Initialize a CSR with the given private key.

    :param privkey: Key to include in the CSR
    :type privkey: :class:`letsencrypt.le_util.Key`

    :param set names: `str` names to include in the CSR

    :param str path: Certificate save directory.

    :returns: CSR
    :rtype: :class:`letsencrypt.le_util.CSR`

    """
    csr_pem, csr_der = make_csr(privkey.pem, names)

    # Save CSR
    le_util.make_or_verify_dir(path, 0o755, os.geteuid())
    csr_f, csr_filename = le_util.unique_file(
        os.path.join(path, csrname), 0o644)
    csr_f.write(csr_pem)
    csr_f.close()

    logger.info("Creating CSR: %s", csr_filename)

    return le_util.CSR(csr_filename, csr_der, "der")


# Lower level functions
def make_csr(key_str, domains):
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
    req.add_extensions([
        OpenSSL.crypto.X509Extension(
            "subjectAltName",
            critical=False,
            value=", ".join("DNS:%s" % d for d in domains)
        ),
    ])
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


def _pyopenssl_load(data, method, types=(
        OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)):
    openssl_errors = []
    for filetype in types:
        try:
            return method(filetype, data), filetype
        except OpenSSL.crypto.Error as error:  # TODO: anything else?
            openssl_errors.append(error)
    raise errors.Error("Unable to load: {0}".format(",".join(
        str(error) for error in openssl_errors)))

def pyopenssl_load_certificate(data):
    """Load PEM/DER certificate.

    :raises errors.Error:

    """
    return _pyopenssl_load(data, OpenSSL.crypto.load_certificate)


def make_ss_cert(key_str, domains, not_before=None,
                 validity=(7 * 24 * 60 * 60)):
    """Returns new self-signed cert in PEM form.

    Uses key_str and contains all domains.

    """
    assert domains, "Must provide one or more hostnames for the cert."
    pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_str)
    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(1337)
    cert.set_version(2)

    extensions = [
        OpenSSL.crypto.X509Extension(
            "basicConstraints", True, 'CA:TRUE, pathlen:0'),
    ]

    cert.get_subject().CN = domains[0]
    # TODO: what to put into cert.get_subject()?
    cert.set_issuer(cert.get_subject())

    if len(domains) > 1:
        extensions.append(OpenSSL.crypto.X509Extension(
            "subjectAltName",
            critical=False,
            value=", ".join("DNS:%s" % d for d in domains)
        ))

    cert.add_extensions(extensions)

    cert.gmtime_adj_notBefore(0 if not_before is None else not_before)
    cert.gmtime_adj_notAfter(validity)

    cert.set_pubkey(pkey)
    cert.sign(pkey, "sha256")
    return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)


def _pyopenssl_cert_or_req_san(cert_or_req):
    """Get Subject Alternative Names from certificate or CSR using pyOpenSSL.

    .. todo:: Implement directly in PyOpenSSL!

    :param cert_or_req: Certificate or CSR.
    :type cert_or_req: `OpenSSL.crypto.X509` or `OpenSSL.crypto.X509Req`.

    :returns: A list of Subject Alternative Names.
    :rtype: list

    """
    # constants based on implementation of
    # OpenSSL.crypto.X509Error._subjectAltNameString
    parts_separator = ", "
    part_separator = ":"
    extension_short_name = "subjectAltName"

    if hasattr(cert_or_req, 'get_extensions'):  # X509Req
        extensions = cert_or_req.get_extensions()
    else:  # X509
        extensions = [cert_or_req.get_extension(i)
                      for i in xrange(cert_or_req.get_extension_count())]

    # pylint: disable=protected-access,no-member
    label = OpenSSL.crypto.X509Extension._prefixes[OpenSSL.crypto._lib.GEN_DNS]
    assert parts_separator not in label
    prefix = label + part_separator

    san_extensions = [
        ext._subjectAltNameString().split(parts_separator)
        for ext in extensions if ext.get_short_name() == extension_short_name]
    # WARNING: this function assumes that no SAN can include
    # parts_separator, hence the split!

    return [part.split(part_separator)[1] for parts in san_extensions
            for part in parts if part.startswith(prefix)]


def _get_sans_from_cert_or_req(
        cert_or_req_str, load_func, typ=OpenSSL.crypto.FILETYPE_PEM):
    try:
        cert_or_req = load_func(typ, cert_or_req_str)
    except OpenSSL.crypto.Error as error:
        logger.exception(error)
        raise
    return _pyopenssl_cert_or_req_san(cert_or_req)


def get_sans_from_cert(cert, typ=OpenSSL.crypto.FILETYPE_PEM):
    """Get a list of Subject Alternative Names from a certificate.

    :param str csr: Certificate (encoded).
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


def asn1_generalizedtime_to_dt(timestamp):
    """Convert ASN.1 GENERALIZEDTIME to datetime.

    Useful for deserialization of `OpenSSL.crypto.X509.get_notAfter` and
    `OpenSSL.crypto.X509.get_notAfter` outputs.

    .. todo:: This function support only one format: `%Y%m%d%H%M%SZ`.
        Implement remaining two.

    """
    return datetime.datetime.strptime(timestamp, '%Y%m%d%H%M%SZ')


def pyopenssl_x509_name_as_text(x509name):
    """Convert `OpenSSL.crypto.X509Name to text."""
    return "/".join("{0}={1}" for key, value in x509name.get_components())
