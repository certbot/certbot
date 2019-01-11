"""Tools for checking certificate revocation."""
import logging
import re
from subprocess import Popen, PIPE

try:
    from cryptography.x509 import ocsp  # pylint: disable=import-error
except ImportError:  # pragma: no cover
    ocsp = None  # type: ignore
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding  # type: ignore
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature
import requests

from acme.magic_typing import Optional, Tuple  # pylint: disable=unused-import, no-name-in-module
from certbot import errors
from certbot import util

logger = logging.getLogger(__name__)


class RevocationChecker(object):
    """This class figures out OCSP checking on this system, and performs it."""

    def __init__(self, enforce_openssl_binary_usage=False):
        self.broken = False
        self.use_openssl_binary = enforce_openssl_binary_usage or not ocsp

        if self.use_openssl_binary:
            if not util.exe_exists("openssl"):
                logger.info("openssl not installed, can't check revocation")
                self.broken = True
                return

            # New versions of openssl want -header var=val, old ones want -header var val
            test_host_format = Popen(["openssl", "ocsp", "-header", "var", "val"],
                                     stdout=PIPE, stderr=PIPE, universal_newlines=True)
            _out, err = test_host_format.communicate()
            if "Missing =" in err:
                self.host_args = lambda host: ["Host=" + host]
            else:
                self.host_args = lambda host: ["Host", host]

    def ocsp_revoked(self, cert_path, chain_path):
        # type: (str, str) -> bool
        """Get revoked status for a particular cert version.

        .. todo:: Make this a non-blocking call

        :param str cert_path: Path to certificate
        :param str chain_path: Path to intermediate cert
        :returns: True if revoked; False if valid or the check failed
        :rtype: bool

        """
        if self.broken:
            return False

        url, host = _determine_ocsp_server(cert_path)
        if not host or not url:
            return False

        if self.use_openssl_binary:
            return self._check_ocsp_openssl_bin(cert_path, chain_path, host, url)
        else:
            return _check_ocsp_cryptography(cert_path, chain_path, url)

    def _check_ocsp_openssl_bin(self, cert_path, chain_path, host, url):
        # type: (str, str, str, str) -> bool
        # jdkasten thanks "Bulletproof SSL and TLS - Ivan Ristic" for documenting this!
        cmd = ["openssl", "ocsp",
               "-no_nonce",
               "-issuer", chain_path,
               "-cert", cert_path,
               "-url", url,
               "-CAfile", chain_path,
               "-verify_other", chain_path,
               "-trust_other",
               "-header"] + self.host_args(host)
        logger.debug("Querying OCSP for %s", cert_path)
        logger.debug(" ".join(cmd))
        try:
            output, err = util.run_script(cmd, log=logger.debug)
        except errors.SubprocessError:
            logger.info("OCSP check failed for %s (are we offline?)", cert_path)
            return False
        return _translate_ocsp_query(cert_path, output, err)


def _check_ocsp_response_signature(response_ocsp, issuer_cert):
    """Verify an OCSP response signature against certificate issuer"""
    try:
        # TODO: (adferrand 2019-11-01) Following line can be improved using a direct call to
        #  response_ocsp.signature_hash_algorithm once cryptography 2.5 is released
        #  (watch out for retro-compatibility with 2.4 though).
        #  See https://github.com/pyca/cryptography/issues/4680
        chosen_hash = x509._SIG_OIDS_TO_HASH[response_ocsp.signature_algorithm_oid]  # pylint: disable=protected-access
    except KeyError:
        raise UnsupportedAlgorithm(
            "Signature algorithm OID:{0} not recognized"
            .format(response_ocsp.signature_algorithm_oid)
        )

    issuer_cert.public_key().verify(
        response_ocsp.signature,
        response_ocsp.tbs_response_bytes,
        padding.PSS(
            mgf=padding.MGF1(chosen_hash),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        chosen_hash
    )


def _determine_ocsp_server(cert_path):
    # type: (str) -> Tuple[Optional[str], Optional[str]]
    """Extract the OCSP server host from a certificate.

    :param str cert_path: Path to the cert we're checking OCSP for
    :rtype tuple:
    :returns: (OCSP server URL or None, OCSP server host or None)

    """
    with open(cert_path, 'rb') as file_handler:
        cert = x509.load_pem_x509_certificate(file_handler.read(), default_backend())
    try:
        extension = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        ocsp_oid = x509.AuthorityInformationAccessOID.OCSP
        descriptions = [description for description in extension.value
                        if description.access_method == ocsp_oid]

        url = descriptions[0].access_location.value
    except (x509.ExtensionNotFound, IndexError):
        logger.info("Cannot extract OCSP URI from %s", cert_path)
        return None, None

    url = url.rstrip()
    host = url.partition("://")[2].rstrip("/")

    if host:
        return url, host
    else:
        logger.info("Cannot process OCSP host from URL (%s) in cert at %s", url, cert_path)
        return None, None


def _check_ocsp_cryptography(cert_path, chain_path, url):
    # type: (str, str, str) -> bool
    # Retrieve OCSP response
    with open(chain_path, 'rb') as file_handler:
        issuer = x509.load_pem_x509_certificate(file_handler.read(), default_backend())
    with open(cert_path, 'rb') as file_handler:
        cert = x509.load_pem_x509_certificate(file_handler.read(), default_backend())
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA1())
    request = builder.build()
    request_binary = request.public_bytes(serialization.Encoding.DER)
    response = requests.post(url, data=request_binary,
                             headers={'Content-Type': 'application/ocsp-request'})
    if response.status_code != 200:
        logger.info("OCSP check failed for %s (are we offline?)", cert_path)
        return False
    response_ocsp = ocsp.load_der_ocsp_response(response.content)

    # Check OCSP response validity
    if response_ocsp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        logger.error("Invalid OCSP response status for %s: %s",
                     cert_path, response_ocsp.response_status)
        return False

    # Check OCSP signature
    try:
        _check_ocsp_response_signature(response_ocsp, issuer)
    except UnsupportedAlgorithm as e:
        logger.error(str(e))
        return False
    except InvalidSignature:
        logger.error('Invalid signature for OCSP response on %s', cert_path)
        return False

    # Check OCSP certificate status
    logger.debug("OCSP certificate status for %s is: %s",
                 cert_path, response_ocsp.certificate_status)
    return response_ocsp.certificate_status == ocsp.OCSPCertStatus.REVOKED


def _translate_ocsp_query(cert_path, ocsp_output, ocsp_errors):
    """Parse openssl's weird output to work out what it means."""

    states = ("good", "revoked", "unknown")
    patterns = [r"{0}: (WARNING.*)?{1}".format(cert_path, s) for s in states]
    good, revoked, unknown = (re.search(p, ocsp_output, flags=re.DOTALL) for p in patterns)

    warning = good.group(1) if good else None

    if ("Response verify OK" not in ocsp_errors) or (good and warning) or unknown:
        logger.info("Revocation status for %s is unknown", cert_path)
        logger.debug("Uncertain output:\n%s\nstderr:\n%s", ocsp_output, ocsp_errors)
        return False
    elif good and not warning:
        return False
    elif revoked:
        warning = revoked.group(1)
        if warning:
            logger.info("OCSP revocation warning: %s", warning)
        return True
    else:
        logger.warning("Unable to properly parse OCSP output: %s\nstderr:%s",
                       ocsp_output, ocsp_errors)
        return False
