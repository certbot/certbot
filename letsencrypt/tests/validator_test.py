"""Tests for letsencrypt.validator."""
import requests
import unittest

import mock

from letsencrypt import errors
from letsencrypt import validator


class ValidatorTest(unittest.TestCase):
    def setUp(self):
        self.validator = validator.Validator()

    @mock.patch("letsencrypt.validator.requests.get")
    def test_succesful_redirect(self, mock_get_request):
        mock_get_request.return_value = create_response(
            301, {"location" : "https://test.com"})
        self.assertTrue(self.validator.redirect("test.com"))

    @mock.patch("letsencrypt.validator.requests.get")
    def test_redirect_missing_location(self, mock_get_request):
        mock_get_request.return_value = create_response(301)
        self.assertFalse(self.validator.redirect("test.com"))

    @mock.patch("letsencrypt.validator.requests.get")
    def test_redirect_wrong_status_code(self, mock_get_request):
        mock_get_request.return_value = create_response(
            201, {"location" : "https://test.com"})
        self.assertFalse(self.validator.redirect("test.com"))

    @mock.patch("letsencrypt.validator.requests.get")
    def test_redirect_wrong_redirect_code(self, mock_get_request):
        mock_get_request.return_value = create_response(
            303, {"location" : "https://test.com"})
        self.assertRaises(
            errors.ValidationError, self.validator.redirect, "test.com")

    @mock.patch("letsencrypt.validator.requests.get")
    def test_https_fail(self, mock_get_request):
        mock_get_request.side_effect = [requests.exceptions.ConnectionError]
        self.assertRaises(
            requests.exceptions.ConnectionError, self.validator.https, "test.com")

    def test_https_success(self):
        with mock.patch("letsencrypt.validator.requests.get"):
            self.assertTrue(self.validator.https(
                "test.com", headers={"Host" : "test.com"}))

    @mock.patch("letsencrypt.validator.requests.get")
    def test_hsts_empty(self, mock_get_request):
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": ""})
        self.assertFalse(self.validator.hsts("test.com"))

    @mock.patch("letsencrypt.validator.requests.get")
    def test_hsts_malformed(self, mock_get_request):
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": "sdfal"})
        self.assertRaises(
            errors.ValidationError, self.validator.hsts, "test.com")

    @mock.patch("letsencrypt.validator.requests.get")
    def test_hsts_bad_max_age(self, mock_get_request):
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": "max-age=not-an-int"})
        self.assertRaises(
            errors.ValidationError, self.validator.hsts, "test.com")

    @mock.patch("letsencrypt.validator.requests.get")
    def test_hsts_expire(self, mock_get_request):
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": "max-age=3600"})
        self.assertRaises(
            errors.ValidationError, self.validator.hsts, "test.com")

    @mock.patch("letsencrypt.validator.requests.get")
    def test_hsts(self, mock_get_request):
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": "max-age=31536000"})
        self.assertTrue(self.validator.hsts("test.com"))

    @mock.patch("letsencrypt.validator.requests.get")
    def test_hsts_include_subdomains(self, mock_get_request):
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security":
                     "max-age=31536000;includeSubDomains"})
        self.assertTrue(self.validator.hsts("test.com"))

    def test_ocsp_stapling(self):
        self.assertRaises(
            NotImplementedError, self.validator.ocsp_stapling, "test.com")

def create_response(status_code=200, headers=None):
    """Creates a requests.Response object for testing"""
    response = requests.Response()
    response.status_code = status_code

    if headers:
        response.headers = headers

    return response


if __name__ == '__main__':
    unittest.main()
