"""Validators to determine the current webserver configuration"""
from subprocess import PIPE, Popen
import zope.interface

import requests

from letsencrypt.client import interfaces
from letsencrypt.client.errors import LetsEncryptValidationError


OCSP_OPENSSL_CMD = "openssl s_client -connect {hostname}:443 -tls1 -tlsextdebug -status"
OCSP_OPENSSL_DELIMITER = "OCSP response:"
OCSP_OPENSSL_NO_RESPONSE = "no response sent"


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
        command = OCSP_OPENSSL_CMD.format(hostname=name).split(" ")
        openssl = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = openssl.communicate("QUIT\n")

        if openssl.returncode != 0:
            raise LetsEncryptValidationError("OpenSSL quit with error-code: {openssl.returncode}.".format(openssl=openssl))

        ocsp_status = next(line for line in stdout.split("\n") if line.startswith(OCSP_OPENSSL_DELIMITER))
        return OCSP_OPENSSL_NO_RESPONSE not in ocsp_status


if __name__ == '__main__':
    print("letsencrypt.org:")
    print(Validator().ocsp_stapling("letsencrypt.org"))
    print(Validator().hsts("letsencrypt.org"))
    print(Validator().https("letsencrypt.org"))
    print(Validator().redirect("letsencrypt.org"))
    print(Validator().ocsp_stapling("letsencrypt.org"))

    print("\ntweakers.net:")
    print(Validator().hsts("tweakers.net"))
    print(Validator().https("tweakers.net"))
    print(Validator().redirect("tweakers.net"))
    print(Validator().ocsp_stapling("tweakers.net"))

    print("\nnon-existing-domain.net:")
    print(Validator().ocsp_stapling("non-existing-domain.net"))

