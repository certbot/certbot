"""Crypto utilities."""
import enum
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import typing
from typing import List
from typing import Literal
from typing import Optional
from typing import Set
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec, ed25519, ed448, types
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import crypto

logger = logging.getLogger(__name__)


class Format(enum.IntEnum):
    """File format to be used when parsing or serializing X.509 structures.

    Backwards compatible with the `FILETYPE_ASN1` and `FILETYPE_PEM` constants
    from pyOpenSSL.
    """
    DER = crypto.FILETYPE_ASN1
    PEM = crypto.FILETYPE_PEM

    def to_cryptography_encoding(self) -> Encoding:
        """Converts the Format to the corresponding cryptography `Encoding`.
        """
        if self == Format.DER:
            return Encoding.DER
        else:
            return Encoding.PEM


# Even *more* annoyingly, due to a mypy bug, we can't use Union[] types in
# isinstance expressions without causing false mypy errors. So we have to
# recreate the type collection as a tuple here. And no, typing.get_args doesn't
# work due to another mypy bug.
#
# mypy issues:
#  * https://github.com/python/mypy/issues/17680
#  * https://github.com/python/mypy/issues/15106
CertificateIssuerPrivateKeyTypesTpl = (
    dsa.DSAPrivateKey,
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
)


def make_csr(
    private_key_pem: bytes,
    domains: Optional[Union[Set[str], List[str]]] = None,
    must_staple: bool = False,
    ipaddrs: Optional[List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]] = None,
) -> bytes:
    """Generate a CSR containing domains or IPs as subjectAltNames.

    Parameters are ordered this way for backwards compatibility when called using positional
    arguments.

    :param buffer private_key_pem: Private key, in PEM PKCS#8 format.
    :param list domains: List of DNS names to include in subjectAltNames of CSR.
    :param bool must_staple: Whether to include the TLS Feature extension (aka
        OCSP Must Staple: https://tools.ietf.org/html/rfc7633).
    :param list ipaddrs: List of IPaddress(type ipaddress.IPv4Address or ipaddress.IPv6Address)
        names to include in subbjectAltNames of CSR.

    :returns: buffer PEM-encoded Certificate Signing Request.

    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, CertificateIssuerPrivateKeyTypesTpl):
        raise ValueError(f"Invalid private key type: {type(private_key)}")
    if domains is None:
        domains = []
    if ipaddrs is None:
        ipaddrs = []
    if len(domains) + len(ipaddrs) == 0:
        raise ValueError(
            "At least one of domains or ipaddrs parameter need to be not empty"
        )

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(d) for d in domains]
                + [x509.IPAddress(i) for i in ipaddrs]
            ),
            critical=False,
        )
    )
    if must_staple:
        builder = builder.add_extension(
            # "status_request" is the feature commonly known as OCSP
            # Must-Staple
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False,
        )

    csr = builder.sign(private_key, hashes.SHA256())
    return csr.public_bytes(Encoding.PEM)


def get_names_from_subject_and_extensions(
    subject: x509.Name, exts: x509.Extensions
) -> List[str]:
    """Gets all DNS SAN names as well as the first Common Name from subject.

    :param subject: Name of the x509 object, which may include Common Name
    :type subject: `cryptography.x509.Name`
    :param exts: Extensions of the x509 object, which may include SANs
    :type exts: `cryptography.x509.Extensions`

    :returns: List of DNS Subject Alternative Names and first Common Name
    :rtype: `list` of `str`
    """
    # We know these are always `str` because `bytes` is only possible for
    # other OIDs.
    cns = [
        typing.cast(str, c.value)
        for c in subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    ]
    try:
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        dns_names = []
    else:
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)

    if not cns:
        return dns_names
    else:
        # We only include the first CN, if there are multiple. This matches
        # the behavior of the previous implementation using pyOpenSSL.
        return [cns[0]] + [d for d in dns_names if d != cns[0]]


def _cryptography_cert_or_req_san(
    cert_or_req: Union[x509.Certificate, x509.CertificateSigningRequest],
) -> List[str]:
    """Get Subject Alternative Names from certificate or CSR using cryptography.

    .. note:: Although this is `acme` internal API, it is used by
        `letsencrypt`.

    :param cert_or_req: Certificate or CSR.
    :type cert_or_req: `x509.Certificate` or `x509.CertificateSigningRequest`.

    :returns: A list of Subject Alternative Names that is DNS.
    :rtype: `list` of `str`

    Deprecated
    .. deprecated: 3.2.1
    """
    # ???: is this translation needed?
    exts = cert_or_req.extensions
    try:
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []

    return san_ext.value.get_values_for_type(x509.DNSName)


# Helper function that can be mocked in unit tests
def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def make_self_signed_cert(private_key: types.CertificateIssuerPrivateKeyTypes,
                          domains: Optional[List[str]] = None,
                          not_before: Optional[datetime] = None,
                          validity: Optional[timedelta] = None, force_san: bool = True,
                          extensions: Optional[List[x509.Extension]] = None,
                          ips: Optional[List[Union[ipaddress.IPv4Address,
                                                   ipaddress.IPv6Address]]] = None
                          ) -> x509.Certificate:
    """Generate new self-signed certificate.
    :param buffer private_key_pem: Private key, in PEM PKCS#8 format.
    :type domains: `list` of `str`
    :param int not_before: A datetime after which the cert is valid. If no
    timezone is specified, UTC is assumed
    :type not_before: `datetime.datetime`
    :param validity: Duration for which the cert will be valid. Defaults to 1
    week
    :type validity: `datetime.timedelta`
    :param buffer private_key_pem: One of
    `cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPrivateKeyTypes`
    :param bool force_san:
    :param extensions: List of additional extensions to include in the cert.
    :type extensions: `list` of `x509.Extension[x509.ExtensionType]`
    :type ips: `list` of (`ipaddress.IPv4Address` or `ipaddress.IPv6Address`)
    If more than one domain is provided, all of the domains are put into
    ``subjectAltName`` X.509 extension and first domain is set as the
    subject CN. If only one domain is provided no ``subjectAltName``
    extension is used, unless `force_san` is ``True``.
    """
    assert domains or ips, "Must provide one or more hostnames or IPs for the cert."

    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())

    if extensions is not None:
        for ext in extensions:
            builder = builder.add_extension(ext.value, ext.critical)
    if domains is None:
        domains = []
    if ips is None:
        ips = []
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)

    name_attrs = []
    if len(domains) > 0:
        name_attrs.append(x509.NameAttribute(
            x509.OID_COMMON_NAME,
            domains[0]
        ))

    builder = builder.subject_name(x509.Name(name_attrs))
    builder = builder.issuer_name(x509.Name(name_attrs))

    sanlist: List[x509.GeneralName] = []
    for address in domains:
        sanlist.append(x509.DNSName(address))
    for ip in ips:
        sanlist.append(x509.IPAddress(ip))
    if force_san or len(domains) > 1 or len(ips) > 0:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sanlist),
            critical=False
        )

    if not_before is None:
        not_before = _now()
    if validity is None:
        validity = timedelta(seconds=7 * 24 * 60 * 60)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_before + validity)

    public_key = private_key.public_key()
    builder = builder.public_key(public_key)
    return builder.sign(private_key, hashes.SHA256())


def dump_cryptography_chain(
    chain: List[x509.Certificate],
    encoding: Literal[Encoding.PEM, Encoding.DER] = Encoding.PEM,
) -> bytes:
    """Dump certificate chain into a bundle.

    :param list chain: List of `cryptography.x509.Certificate`.

    :returns: certificate chain bundle
    :rtype: bytes

    Deprecated
    .. deprecated: 3.2.1
    """
    # XXX: returns empty string when no chain is available, which
    # shuts up RenewableCert, but might not be the best solution...

    def _dump_cert(cert: x509.Certificate) -> bytes:
        return cert.public_bytes(encoding)

    # assumes that x509.Certificate.public_bytes includes ending
    # newline character
    return b"".join(_dump_cert(cert) for cert in chain)
