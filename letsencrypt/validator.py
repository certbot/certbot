"""Validators to determine the current webserver configuration"""
import requests
import zope.interface

from letsencrypt import errors
from letsencrypt import interfaces


class Validator(object):
    # pylint: disable=no-self-use
    """Collection of functions to test a live webserver's configuration"""
    zope.interface.implements(interfaces.IValidator)

    def redirect(self, hostname, port=80, headers=None):
        """Test whether webserver redirects to secure connection."""
        response = _get("http", hostname, port, headers)

        if response.status_code not in (301, 303):
            return False

        redirect_location = response.headers.get("location", "")
        if not redirect_location.startswith("https://"):
            return False

        if response.status_code != 301:
            error_msg = "Server did not redirect with permanent code."
            raise errors.ValidationError(error_msg)

        return True

    def https(self, hostname, port=443, headers=None):
        """Test whether webserver supports HTTPS"""
        _get("https", hostname, port, headers)
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
            raise errors.ValidationError(error_msg)

        try:
            _, max_age_value = max_age[0]
            max_age_value = int(max_age_value)
        except ValueError:
            error_msg = "Server responded with invalid HSTS header field."
            raise errors.ValidationError(error_msg)

        # Test whether HSTS does not expire for at least two weeks.
        if max_age_value <= (2 * 7 * 24 * 3600):
            error_msg = "HSTS should not expire in less than two weeks."
            raise errors.ValidationError(error_msg)

        return True

    def ocsp_stapling(self, name):
        """Verify ocsp stapling for domain."""
        raise NotImplementedError()


def _get(scheme, hostname, port, headers, **kwargs):
    """Makes a GET request for specified resource"""
    url = "{0}://{1}:{2}".format(scheme, hostname, port)
    if headers:
        return requests.get(url, headers=headers, **kwargs)
    else:
        return requests.get(url, **kwargs)
