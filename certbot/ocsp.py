"""Tools for checking certificate revocation."""
import logging

from certbot import errors
from certbot import util

logger = logging.getLogger(__name__)


REV_LABEL = "**Revoked**"
EXP_LABEL = "**Expired**"

INSTALL_LABEL = "(Installed)"


def revoked_status(cert_path, chain_path):
    """Get revoked status for a particular cert version.

    .. todo:: Make this a non-blocking call

    :param str cert_path: Path to certificate
    :param str chain_path: Path to chain certificate

    """
    url, _ = util.run_script(
        ["openssl", "x509", "-in", cert_path, "-noout", "-ocsp_uri"])

    url = url.rstrip()
    host = url.partition("://")[2].rstrip("/")
    if not host:
        raise errors.Error(
            "Unable to get OCSP host from cert, url - %s", url)

    # This was a PITA...
    # Thanks to "Bulletproof SSL and TLS - Ivan Ristic" for helping me out
    try:
        output, _ = util.run_script(
            ["openssl", "ocsp",
            "-no_nonce", "-header", "Host", host,
            "-issuer", chain_path,
            "-cert", cert_path,
            "-url", url,
            "-CAfile", chain_path,
            "-verify_other", chain_path])
    except errors.SubprocessError:
        return "OCSP Failure"

    return _translate_ocsp_query(cert_path, output)


def _translate_ocsp_query(cert_path, ocsp_output):
    """Returns a label string out of the query."""
    if not "Response verify OK":
        return "Revocation Unknown"
    if cert_path + ": good" in ocsp_output:
        return ""
    elif cert_path + ": revoked" in ocsp_output:
        return REV_LABEL
    else:
        raise errors.Error(
            "Unable to properly parse OCSP output: %s", ocsp_output)

