import unittest

import responses
from requests.exceptions import ConnectionError
from letsencrypt.client.errors import LetsEncryptValidationError
from letsencrypt.client.validator import Validator


def _add(secure=False, **kwargs):
    url = "{}://test.com".format("https" if secure else "http")
    return responses.add(responses.GET, url, **kwargs)


class ValidatorTest(unittest.TestCase):
    @responses.activate
    def test_succesful_redirect(self):
        _add(status=301, adding_headers={"location": "https://test.com"})
        self.assertTrue(Validator().redirect("test.com"))

    @responses.activate
    def test_redirect_missing_location(self):
        _add(status=301)
        self.assertFalse(Validator().redirect("test.com"))

    @responses.activate
    def test_redirect_wrong_status_code(self):
        _add(status=201, adding_headers={"location": "https://test.com"})
        self.assertFalse(Validator().redirect("test.com"))

    @responses.activate
    def test_redirect_wrong_redirect_code(self):
        _add(status=303, adding_headers={"location": "https://test.com"})
        self.assertRaises(LetsEncryptValidationError, Validator().redirect, "test.com")

    @responses.activate
    def test_https_fail(self):
        self.assertRaises(ConnectionError, Validator().https, "test.com")

    @responses.activate
    def test_https_success(self):
        _add(secure=True, body="blaa")
        self.assertTrue(Validator().https("test.com"))

    @responses.activate
    def test_hsts_empty(self):
        _add(secure=True, adding_headers={"strict-transport-security": ""})
        self.assertFalse(Validator().hsts("test.com"))

    @responses.activate
    def test_hsts_malformed(self):
        _add(secure=True, adding_headers={"strict-transport-security": "sdfal"})
        self.assertRaises(LetsEncryptValidationError, Validator().hsts, "test.com")

    @responses.activate
    def test_hsts_expire(self):
        _add(secure=True, adding_headers={"strict-transport-security": "max-age=3600"})
        self.assertRaises(LetsEncryptValidationError, Validator().hsts, "test.com")

    @responses.activate
    def test_hsts(self):
        _add(secure=True, adding_headers={"strict-transport-security": "max-age=31536000"})
        self.assertTrue(Validator().hsts("test.com"))

    @responses.activate
    def test_hsts(self):
        headers = {"strict-transport-security": "max-age=31536000;includeSubDomains"}
        _add(secure=True, adding_headers=headers)
        self.assertTrue(Validator().hsts("test.com"))


if __name__ == '__main__':
    unittest.main()
