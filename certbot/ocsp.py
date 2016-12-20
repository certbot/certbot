"""Tools for checking certificate revocation."""
import logging

from subprocess import Popen, PIPE

from certbot import errors
from certbot import util

logger = logging.getLogger(__name__)


REV_LABEL = "REVOKED"

INSTALL_LABEL = "(Installed)"

class RevocationChecker(object):
    "This class figures out OCSP checking on this system, and performs it."

    def __init__(self, config):
        self.broken = False
        self.config = config

        if not util.exe_exists("openssl"):
            logging.info("openssl not installed, can't check revocation")
            self.broken = True
            return

       # New versions of openssl want -header var=val, old ones want -header var val
        test_host_format = Popen(["openssl", "ocsp", "-header", "var", "val"],
                                 stdout=PIPE, stderr=PIPE)
        _out, err = test_host_format.communicate()
        if "Missing =" in err:
            self.host_args = lambda host: ["Host=" + host]
        else:
            self.host_args = lambda host: ["Host", host]


    def ocsp_status(self, cert_path, chain_path, status_in):
        """Helper function: updates a cert status string with revocation information

        :param str cert_path: path to a cert to check
        :param str chain_path: issuing intermediate for the cert
        :param str status_in: a string that is either empty, if the cert is otherwise
                              believed to be valid, or 'INVALID: $REASON'.

        :returns: a new status including revocation, if the cert is revoked."""

        if self.config.check_ocsp.lower() == "never":
            return status_in
        elif self.config.check_ocsp.lower() == "lazy" and status_in:
            return status_in

        revoked = self.check_ocsp(cert_path, chain_path)
        if not revoked:
            return status_in
        elif status_in:
            return status_in + ",REVOKED"
        else:
            return "INVALID: REVOKED"


    def check_ocsp(self, cert_path, chain_path):
        """Get revoked status for a particular cert version.

        .. todo:: Make this a non-blocking call

        :param str cert_path: Path to certificate
        :param str chain_path: Path to intermediate cert

        """
        if self.broken:
            return False

        logger.debug("Querying OCSP for %s", cert_path)
        url, host = self.determine_ocsp_server(cert_path)
        if not host:
            return False
        # jdkasten thanks "Bulletproof SSL and TLS - Ivan Ristic" for documenting this!
        cmd = ["openssl", "ocsp",
               "-no_nonce",
               "-issuer", chain_path,
               "-cert", cert_path,
               "-url", url,
               "-CAfile", chain_path,
               "-verify_other", chain_path,
               "-header"] + self.host_args(host)
        try:
            output, err = util.run_script(cmd, log=logging.debug)
        except errors.SubprocessError, e:
            logger.info("OCSP check failed for %s (are we offline?)", cert_path)
            logger.debug("Command was:\n%s\nError was:\n%s", " ".join(cmd), e)
            return False

        return _translate_ocsp_query(cert_path, output, err)


    def determine_ocsp_server(self, cert_path):
        """Extract the OCSP server host from a certificate.

        :param str cert_path: Path to the cert we're checking OCSP for
        :rtype tuple:
        :returns: (OCSP server URL or None, OCSP server host or None)

        """
        try:
            url, err = util.run_script(
                ["openssl", "x509", "-in", cert_path, "-noout", "-ocsp_uri"],
                log=logging.debug)
        except errors.SubprocessError:
            logger.info("Cannot extract OCSP URI from %s", cert_path)
            logger.debug("Error was:\n%s", err)
            return None, None

        url = url.rstrip()
        host = url.partition("://")[2].rstrip("/")
        if host:
            return url, host
        else:
            logger.info("Cannot process OCSP host from URL (%s) in cert at %s", url, cert_path)
            return None, None


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

