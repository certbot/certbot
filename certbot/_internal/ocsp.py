"""Tools for checking certificate revocation."""
import logging
import re
from datetime import datetime, timedelta
from subprocess import Popen, PIPE

try:
    # Only cryptography>=2.5 has ocsp module
    # and signature_hash_algorithm attribute in OCSPResponse class
    from cryptography.x509 import ocsp  # pylint: disable=import-error
    getattr(ocsp.OCSPResponse, 'signature_hash_algorithm')
except (ImportError, AttributeError):  # pragma: no cover
    ocsp = None  # type: ignore
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature
import pytz
import requests

from acme.magic_typing import Optional, Tuple  # pylint: disable=unused-import, no-name-in-module
from certbot import crypto_util
from certbot import errors
from certbot._internal.storage import RenewableCert # pylint: disable=unused-import
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

    def ocsp_revoked(self, cert):
        # type: (RenewableCert) -> bool
        """Get revoked status for a particular cert version.

        .. todo:: Make this a non-blocking call

        :param `.storage.RenewableCert` cert: Certificate object
        :returns: True if revoked; False if valid or the check failed or cert is expired.
        :rtype: bool

        """
        cert_path, chain_path = cert.cert, cert.chain

        if self.broken:
            return False

        # Let's Encrypt doesn't update OCSP for expired certificates,
        # so don't check OCSP if the cert is expired.
        # https://github.com/certbot/certbot/issues/7152
        now = pytz.UTC.fromutc(datetime.utcnow())
        if cert.target_expiry <= now:
            return False

        url, host = _determine_ocsp_server(cert_path)
        if not host or not url:
            return False

        if self.use_openssl_binary:
            return self._check_ocsp_openssl_bin(cert_path, chain_path, host, url)
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
    try:
        response = requests.post(url, data=request_binary,
                                 headers={'Content-Type': 'application/ocsp-request'})
    except requests.exceptions.RequestException:
        logger.info("OCSP check failed for %s (are we offline?)", cert_path, exc_info=True)
        return False
    if response.status_code != 200:
        logger.info("OCSP check failed for %s (HTTP status: %d)", cert_path, response.status_code)
        return False

    response_ocsp = ocsp.load_der_ocsp_response(response.content)

    # Check OCSP response validity
    if response_ocsp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        logger.error("Invalid OCSP response status for %s: %s",
                     cert_path, response_ocsp.response_status)
        return False

    # Check OCSP signature
    try:
        _check_ocsp_response(response_ocsp, request, issuer, cert_path)
    except UnsupportedAlgorithm as e:
        logger.error(str(e))
    except errors.Error as e:
        logger.error(str(e))
    except InvalidSignature:
        logger.error('Invalid signature on OCSP response for %s', cert_path)
    except AssertionError as error:
        logger.error('Invalid OCSP response for %s: %s.', cert_path, str(error))
    else:
        # Check OCSP certificate status
        logger.debug("OCSP certificate status for %s is: %s",
                     cert_path, response_ocsp.certificate_status)
        return response_ocsp.certificate_status == ocsp.OCSPCertStatus.REVOKED

    return False


def _check_ocsp_response(response_ocsp, request_ocsp, issuer_cert, cert_path):
    """Verify that the OCSP is valid for serveral criterias"""
    # Assert OCSP response corresponds to the certificate we are talking about
    if response_ocsp.serial_number != request_ocsp.serial_number:
        raise AssertionError('the certificate in response does not correspond '
                             'to the certificate in request')

    # Assert signature is valid
    _check_ocsp_response_signature(response_ocsp, issuer_cert, cert_path)

    # Assert issuer in response is the expected one
    if (not isinstance(response_ocsp.hash_algorithm, type(request_ocsp.hash_algorithm))
            or response_ocsp.issuer_key_hash != request_ocsp.issuer_key_hash
            or response_ocsp.issuer_name_hash != request_ocsp.issuer_name_hash):
        raise AssertionError('the issuer does not correspond to issuer of the certificate.')

    # In following checks, two situations can occur:
    #   * nextUpdate is set, and requirement is thisUpdate < now < nextUpdate
    #   * nextUpdate is not set, and requirement is thisUpdate < now
    # NB1: We add a validity period tolerance to handle clock time inconsistencies,
    #      value is 5 min like for OpenSSL.
    # NB2: Another check is to verify that thisUpdate is not too old, it is optional
    #      for OpenSSL, so we do not do it here.
    # See OpenSSL implementation as a reference:
    # https://github.com/openssl/openssl/blob/ef45aa14c5af024fcb8bef1c9007f3d1c115bd85/crypto/ocsp/ocsp_cl.c#L338-L391
    now = datetime.utcnow()  # thisUpdate/nextUpdate are expressed in UTC/GMT time zone
    if not response_ocsp.this_update:
        raise AssertionError('param thisUpdate is not set.')
    if response_ocsp.this_update > now + timedelta(minutes=5):
        raise AssertionError('param thisUpdate is in the future.')
    if response_ocsp.next_update and response_ocsp.next_update < now - timedelta(minutes=5):
        raise AssertionError('param nextUpdate is in the past.')


def _check_ocsp_response_signature(response_ocsp, issuer_cert, cert_path):
    """Verify an OCSP response signature against certificate issuer or responder"""
    if response_ocsp.responder_name == issuer_cert.subject:
        # Case where the OCSP responder is also the certificate issuer
        logger.debug('OCSP response for certificate %s is signed by the certificate\'s issuer.',
                     cert_path)
        responder_cert = issuer_cert
    else:
        # Case where the OCSP responder is not the certificate issuer
        logger.debug('OCSP response for certificate %s is delegated to an external responder.',
                     cert_path)

        responder_certs = [cert for cert in response_ocsp.certificates
                           if cert.subject == response_ocsp.responder_name]
        if not responder_certs:
            raise AssertionError('no matching responder certificate could be found')

        # We suppose here that the ACME server support only one certificate in the OCSP status
        # request. This is currently the case for LetsEncrypt servers.
        # See https://github.com/letsencrypt/boulder/issues/2331
        responder_cert = responder_certs[0]

        if responder_cert.issuer != issuer_cert.subject:
            raise AssertionError('responder certificate is not signed '
                                 'by the certificate\'s issuer')

        try:
            extension = responder_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            delegate_authorized = x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING in extension.value
        except (x509.ExtensionNotFound, IndexError):
            delegate_authorized = False
        if not delegate_authorized:
            raise AssertionError('responder is not authorized by issuer to sign OCSP responses')

        # Following line may raise UnsupportedAlgorithm
        chosen_hash = responder_cert.signature_hash_algorithm
        # For a delegate OCSP responder, we need first check that its certificate is effectively
        # signed by the certificate issuer.
        crypto_util.verify_signed_payload(issuer_cert.public_key(), responder_cert.signature,
                                          responder_cert.tbs_certificate_bytes, chosen_hash)

    # Following line may raise UnsupportedAlgorithm
    chosen_hash = response_ocsp.signature_hash_algorithm
    # We check that the OSCP response is effectively signed by the responder
    # (an authorized delegate one or the certificate issuer itself).
    crypto_util.verify_signed_payload(responder_cert.public_key(), response_ocsp.signature,
                                      response_ocsp.tbs_response_bytes, chosen_hash)


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
