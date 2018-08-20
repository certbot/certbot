"""Tools for checking certificate revocation."""
import logging
import os
import re

from subprocess import Popen, PIPE

from certbot import crypto_util
from certbot import errors
from certbot import util

from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

logger = logging.getLogger(__name__)

class OCSPBase(object):
    """Base class for OCSP request operations"""

    def determine_ocsp_server(self, cert_path):
        """Extract the OCSP server host from a certificate.

        :param str cert_path: Path to the cert we're checking OCSP for
        :rtype tuple:
        :returns: (OCSP server URL or None, OCSP server host or None)

        """
        url = None
        cert = crypto_util.load_cert(cert_path)
        ocsp_authinfo = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for obj in ocsp_authinfo.value:
            if obj.access_method == AuthorityInformationAccessOID.OCSP:
                url = obj.access_location.value

        url = url.strip()
        host = url.partition("://")[2].rstrip("/")
        if host:
            return url, host
        else:
            logger.info("Cannot process OCSP host from URL (%s) in cert at %s", url, cert_path)
            return None, None

    def _request_status(self, response):
        """Checks that the OCSP response was successful from the text output"""
        pattern = re.compile(r"OCSP Response Status: (.*)\n")
        return "successful (0x0)" in pattern.findall(response)

    def _response_successful(self, response, cert_path):
        """Checks that the certificate is not revoked"""
        pattern = re.compile(r"{0}: (.*)\n".format(cert_path))
        if "revoked" in pattern.findall(response):
            raise errors.OCSPRevokedError("Certificate is revoked")
        return "good" in pattern.findall(response)

class OCSPResponseHandler(OCSPBase):
    """Class for handling OCSP requests"""
    def __init__(self, cert_path, chain_path):
        self.cert_path = cert_path
        self.chain_path = chain_path

    def ocsp_request_to_file(self, filepath):
        """Make OCSP request and save the response to a file.

        :param str filepath: Path to save the OCSP response to.

        :returns: True if the response was successfully saved
        :rtype: bool

        :raises errors.OCSPRevokedError: If certificate is revoked.

        """

        url, _ = self.determine_ocsp_server(self.cert_path)
        cmd = ["openssl", "ocsp",
               "-no_nonce",
               "-issuer", self.chain_path,
               "-cert", self.cert_path,
               "-url", url,
               "-CAfile", self.chain_path,
               "-verify_other", self.chain_path,
               "-trust_other",
               "-respout", filepath,
               "-text"]
        try:
            output, _ = util.run_script(cmd, log=logger.debug)
        except errors.SubprocessError:
            logger.info("OCSP check failed for %s (are we offline?)", self.cert_path)
            return False

        if not self._request_status(output):
            raise errors.OCSPRequestError("OCSP request returned an error")
        try:
            if self._response_successful(output, self.cert_path):
                return os.path.isfile(filepath)
        except errors.OCSPRevokedError:
            logger.warning("Certificate %s is revoked.", self.cert_path)
            raise
        return False


class RevocationChecker(OCSPBase):
    "This class figures out OCSP checking on this system, and performs it."

    def __init__(self):
        self.broken = False

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
        """Get revoked status for a particular cert version.

        .. todo:: Make this a non-blocking call

        :param str cert_path: Path to certificate
        :param str chain_path: Path to intermediate cert
        :rtype bool or None:
        :returns: True if revoked; False if valid or the check failed

        """
        if self.broken:
            return False


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


def _translate_ocsp_query(cert_path, ocsp_output, ocsp_errors):
    """Parse openssl's weird output to work out what it means."""

    states = ("good", "revoked", "unknown")
    patterns = [r"{0}: (WARNING.*)?{1}".format(cert_path, s) for s in states]
    good, revoked, unknown = (re.search(p, ocsp_output, flags=re.DOTALL) for p in patterns)

    warning = good.group(1) if good else None

    if (not "Response verify OK" in ocsp_errors) or (good and warning) or unknown:
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
        logger.warn("Unable to properly parse OCSP output: %s\nstderr:%s",
                    ocsp_output, ocsp_errors)
        return False

