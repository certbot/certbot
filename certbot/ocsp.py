"""Tools for checking certificate revocation."""
import logging

from subprocess import Popen, PIPE

from certbot import errors
from certbot import util

logger = logging.getLogger(__name__)


REV_LABEL = "REVOKED"

INSTALL_LABEL = "(Installed)"


def revoked_status(cert_path, chain_path):
    """Get revoked status for a particular cert version.

    .. todo:: Make this a non-blocking call

    :param str cert_path: Path to certificate
    :param str chain_path: Path to chain certificate

    """

    if revoked_status.broken:
        return False

    if not util.exe_exists("openssl"):
        logging.info("openssl not installed, can't check revocation")
        revoked_status.broken = True
        return False

    try:
        url, err = util.run_script(
            ["openssl", "x509", "-in", cert_path, "-noout", "-ocsp_uri"],
            log=logging.debug)
    except errors.SubprocessError:
        logger.info("Cannot extract OCSP URI from %s", cert_path)
        return False

    url = url.rstrip()
    host = url.partition("://")[2].rstrip("/")
    if not host:
        logger.info("Cannot process OCSP host from URL (%s) in cert at %s", url, cert_path)
        return False

    # New versions of openssl want -header var=val, old ones want -header var val
    test_host_format = Popen(["openssl", "ocsp", "-header", "var", "val"],
                             stdout=PIPE, stderr=PIPE)
    _out, err = test_host_format.communicate()
    if "Missing =" in err:
        host_args = ["Host=" + host]
    else:
        host_args = ["Host", host]

    # jdkasten thanks "Bulletproof SSL and TLS - Ivan Ristic" for documenting this!
    try:
        cmd = ["openssl", "ocsp",
               "-no_nonce",
               "-issuer", chain_path,
               "-cert", cert_path,
               "-url", url,
               "-CAfile", chain_path,
               "-verify_other", chain_path,
               "-header"] + host_args
        output, err = util.run_script(cmd, log=logging.debug)
    except errors.SubprocessError:
        logger.info("OCSP querying seems to be broken, assuming nothing is revoked...")
        logger.debug("Command was:\n%s\nError was:\n%s", " ".join(cmd), err)
        revoked_status.broken = True
        return False

    return _translate_ocsp_query(cert_path, output, err)
revoked_status.broken = False


def _translate_ocsp_query(cert_path, ocsp_output, ocsp_errors):
    """Returns a label string out of the query."""
    if not "Response verify OK":
        logger.info("Revocation status for %s is unknown", cert_path)
        logger.debug("Uncertain ouput:\n%s\nstderr:\n%s", ocsp_output, ocsp_errors)
        return ""
    if cert_path + ": good" in ocsp_output:
        return ""
    elif cert_path + ": revoked" in ocsp_output:
        return REV_LABEL
    else:
        logger.warn("Unable to properly parse OCSP output: %s", ocsp_output)
        return ""

