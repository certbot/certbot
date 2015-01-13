"""Validators to determine the current webserver configuration"""
from subprocess import PIPE, Popen
import logging

import requests
import zope.interface

from letsencrypt.client import interfaces
from letsencrypt.client.errors import LetsEncryptValidationError

log = logging.getLogger(__name__)

OCSP_OPENSSL_CMD = "openssl s_client -connect {hostname}:443"
OCSP_OPENSSL_DELIMITER = "OCSP response:"
OCSP_OPENSSL_NO_RESPONSE = "no response sent"
PROTOCOLS_OPENSSL_DELIMITER = "Protocols advertised by server:"
SPDY_PROTOCOLS = {"spdy/3.1", "spdy/3"}

def _openssl(hostname, args, input=None):
    """
    Call openssl binary in client mode.

    :raises LetsEncryptValidationError if openssl exits with error-code
    :param hostname: server to connect to (on port 443)
    :param args: arguments (list) to append to default ones
    :param input: stdin to binary
    :return: (stdout, stderr)
    """
    openssl_cmd = OCSP_OPENSSL_CMD.format(hostname=hostname).split(" ") + list(args)

    log.debug("Calling openssl binary with arguments: " + str(openssl_cmd[1:]))
    openssl = Popen(openssl_cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = openssl.communicate(input=input)
    log.debug("OpenSSL stdout: " + stdout)
    log.debug("OpenSSL stderr: " + stderr)

    if openssl.returncode != 0:
        raise LetsEncryptValidationError("OpenSSL quit with error-code: {openssl.returncode}.".format(openssl=openssl))

    return stdout, stderr


class Validator(object):
    zope.interface.implements(interfaces.IValidator)

    def redirect(self, name):
        response = requests.get("http://" + name, allow_redirects=False)

        if response.status_code not in (301, 303):
            return False

        redirect_location = response.headers.get("location", "")
        if not redirect_location.startswith("https://"):
            return False

        if response.status_code != 301:
            raise LetsEncryptValidationError("Server did not redirect with permanent code.")

        return True

    def https(self, name):
        requests.get("https://" + name, verify=True)
        return True

    def hsts(self, name):
        headers = requests.get("https://" + name).headers
        hsts_header = headers.get("strict-transport-security")
        
        if not hsts_header:
            return False

        # Split directives following RFC6797, section 6.1
        directives = [d.split("=") for d in hsts_header.split(";")]
        max_age = [d for d in directives if d[0] == "max-age"][0]
        
        try:
            max_age_name, max_age_value = max_age
            max_age_value = int(max_age_value)
        except ValueError:
            raise LetsEncryptValidationError("Server responded with invalid HSTS header field.")

        return True

    def ocsp_stapling(self, name):
        stdout, stderr = _openssl(name, ["-tls1", "-tlsextdebug", "-status"], input="QUIT\n")
        ocsp_status = next(line for line in stdout.split("\n") if line.startswith(OCSP_OPENSSL_DELIMITER))
        return OCSP_OPENSSL_NO_RESPONSE not in ocsp_status

    def _get_nextgen_protocols(self, name):
        """Return a set with all 'nextgen' protocols supported by server (reported by openssl)."""
        stdout, stderr = _openssl(name, ["-nextprotoneg", "''"], input="QUIT\n")
        delimiter_line = list(line for line in stdout.split("\n") if line.startswith(PROTOCOLS_OPENSSL_DELIMITER))

        if not delimiter_line:
            return set()

        protocols = delimiter_line[0].split(PROTOCOLS_OPENSSL_DELIMITER)[1]
        return {p.strip() for p in protocols.split(",")}

    def spdy(self, name):
        # SPDY is supported if we recognise at least one protocol
        return bool(self._get_nextgen_protocols(name) & SPDY_PROTOCOLS)



if __name__ == '__main__':
    print("letsencrypt.org:")
    print(Validator().ocsp_stapling("letsencrypt.org"))
    print(Validator().hsts("letsencrypt.org"))
    print(Validator().https("letsencrypt.org"))
    print(Validator().redirect("letsencrypt.org"))
    print(Validator().ocsp_stapling("letsencrypt.org"))
    print(Validator().spdy("letsencrypt.org"))
    print(Validator()._get_nextgen_protocols("letsencrypt.org"))

    print("\ntweakers.net:")
    print(Validator().hsts("tweakers.net"))
    print(Validator().https("tweakers.net"))
    print(Validator().redirect("tweakers.net"))
    print(Validator().ocsp_stapling("tweakers.net"))
    print(Validator().spdy("tweakers.net"))
    print(Validator()._get_nextgen_protocols("tweakers.net"))

    print("\nnon-existing-domain.net:")
    print(Validator().ocsp_stapling("non-existing-domain.net"))

