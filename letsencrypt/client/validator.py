"""Validators to determine the current webserver configuration"""
import zope.interface
import requests
from letsencrypt.client import interfaces


class ValidationError(Exception):
    pass


class Validator(object):
    zope.interface.implements(interfaces.IValidator)

    def redirect(self, name):
        response = requests.get("http://" + name, allow_redirects=False)

        if response.status_code not in (301, 303):
            raise ValidationError("Server did not respond with redirect code.")

        if response.status_code != 301:
            raise ValidationError("Server did not redirect with permanent code.")

        redirect_location = response.headers.get("location", "")
        if not redirect_location.startswith("https://"):
            raise ValidationError("Server did not redirect to HTTPS connection.")

        return True

    def https(self, names):
        for name in names:
            request.get("https://" + name, verify=True)
        return True

    def hsts(self, name):
        headers = requests.get("https://" + name, verify=False).headers
        hsts_header = headers.get("strict-transport-security")
        
        if not hsts_headers:
            raise ValidationError("Server responed with either no or an empty HSTS header.")

        # Split directives following RFC6797, section 6.1
        directives = [d.split("=") for d in hsts_headers.split(";")]
        max_age = [d for d in directives if d[0] == "max-age"][0]
        
        try:
            max_age_name, max_age_value = max_age
            max_age_value = int(max_age_value)
        except ValueError:
            raise ValidationError("Server responed with invalid HSTS header field.")

        return True

    def ocsp_stapling(self):
        raise NotImplementedError("OCSP checking not yet implemented.")

