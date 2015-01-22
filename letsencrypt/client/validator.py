"""Validators to determine the current webserver configuration"""
from subprocess import PIPE, Popen
import logging
import re

import requests
import zope.interface

from letsencrypt.client import interfaces
from letsencrypt.client.errors import LetsEncryptValidationError

log = logging.getLogger(__name__)

OCSP_OPENSSL_CMD = "openssl s_client -connect {hostname}:443"
OCSP_OPENSSL_DELIMITER = "OCSP response:"
OCSP_OPENSSL_NO_RESPONSE = "no response sent"
PROTOCOLS_OPENSSL_DELIMITER = "Protocols advertised by server:"
SPDY_PROTOCOL_RE = re.compile(r"^spdy/\d(\.\d)?$")


def _openssl(hostname, args, input=None):
    """
    Call openssl binary in client mode.

    :raises LetsEncryptValidationError if openssl exits with error-code
    :param hostname: server to connect to (on port 443)
    :param args: arguments (list) to append to default ones
    :param input: stdin to binary
    :return: (stdout, stderr)
    """
    openssl_cmd = OCSP_OPENSSL_CMD.format(**locals()).split(" ") + list(args)

    log.debug("Calling openssl binary with arguments: %s", openssl_cmd[1:])
    openssl = Popen(openssl_cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = openssl.communicate(input=input)
    log.debug("OpenSSL stdout: %s", stdout)
    log.debug("OpenSSL stderr: %s", stderr)

    if openssl.returncode != 0:
        error_msg = "OpenSSL quit with error-code: {openssl.returncode}"
        raise LetsEncryptValidationError(error_msg.format(openssl=openssl))

    return stdout, stderr


def _filter_startswith(strings, start):
    """Yields all strings which start with given string."""
    for string in strings:
        if string.startswith(start):
            yield string


class Validator(object):
    """Collection of functions to test a live webserver's configuration"""
    zope.interface.implements(interfaces.IValidator)

    def redirect(self, hostname):
        """Test whether webserver redirects to secure connection."""
        response = requests.get("http://" + hostname, allow_redirects=False)

        if response.status_code not in (301, 303):
            return False

        redirect_location = response.headers.get("location", "")
        if not redirect_location.startswith("https://"):
            return False

        if response.status_code != 301:
            error_msg = "Server did not redirect with permanent code."
            raise LetsEncryptValidationError(error_msg)

        return True

    def https(self, hostname):
        """Test whether webserver supports HTTPS"""
        requests.get("https://" + hostname, verify=True)
        return True

    def hsts(self, hostname):
        """Test for HTTP Strict Transport Security header"""
        headers = requests.get("https://" + hostname).headers
        hsts_header = headers.get("strict-transport-security")

        if not hsts_header:
            return False

        # Split directives following RFC6797, section 6.1
        directives = [d.split("=") for d in hsts_header.split(";")]
        max_age = [d for d in directives if d[0] == "max-age"]

        if not max_age:
            error_msg = "Server responded with invalid HSTS header field."
            raise LetsEncryptValidationError(error_msg)

        try:
            max_age_name, max_age_value = max_age[0]
            max_age_value = int(max_age_value)
        except ValueError:
            error_msg = "Server responded with invalid HSTS header field."
            raise LetsEncryptValidationError(error_msg)

        # Test whether HSTS does not expire for at least two weeks.
        if max_age_value <= (2 * 7 * 24 * 3600):
            error_msg = "HSTS should not expire in less than two weeks."
            raise LetsEncryptValidationError(error_msg)

        return True

    def ocsp_stapling(self, hostname):
        """Test for OCSP stapling. See RFC 6066, section 8."""
        stdout, stderr = _openssl(hostname, ["-tls1", "-tlsextdebug", "-status"], input="QUIT\n")
        ocsp_status = next(_filter_startswith(stdout.split("\n"), OCSP_OPENSSL_DELIMITER))
        return OCSP_OPENSSL_NO_RESPONSE not in ocsp_status

    def _get_nextgen_protocols(self, hostname):
        """Return a set with all 'nextgen' protocols supported by server (reported by openssl)."""
        stdout, stderr = _openssl(hostname, ["-nextprotoneg", "''"], input="QUIT\n")
        delimiter_line = list(_filter_startswith(stdout.split("\n"), PROTOCOLS_OPENSSL_DELIMITER))

        if not delimiter_line:
            return set()

        protocols = delimiter_line[0].split(PROTOCOLS_OPENSSL_DELIMITER)[1]
        return set(p.strip() for p in protocols.split(","))

    def spdy(self, hostname):
        """Test for SPDY support"""
        # SPDY is supported if we recognise at least one protocol
        next_gen_protocols = self._get_nextgen_protocols(hostname)
        spdy_protocols = filter(SPDY_PROTOCOL_RE.match, next_gen_protocols)
        return bool(list(spdy_protocols))
