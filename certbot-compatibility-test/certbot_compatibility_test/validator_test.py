"""Tests for certbot_compatibility_test.validator."""
from typing import cast
from typing import Mapping
from typing import Optional
import unittest
from unittest import mock

from OpenSSL import crypto
import requests

from acme import errors as acme_errors
from certbot_compatibility_test import validator


class ValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = validator.Validator()

    @mock.patch(
        "certbot_compatibility_test.validator.crypto_util.probe_sni")
    def test_certificate_success(self, mock_probe_sni: mock.MagicMock) -> None:
        cert = crypto.X509()
        mock_probe_sni.return_value = cert
        self.assertTrue(self.validator.certificate(
            cert, "test.com", "127.0.0.1"))

    @mock.patch(
        "certbot_compatibility_test.validator.crypto_util.probe_sni")
    def test_certificate_error(self, mock_probe_sni: mock.MagicMock) -> None:
        cert = crypto.X509()
        mock_probe_sni.side_effect = [acme_errors.Error]
        self.assertFalse(self.validator.certificate(
            cert, "test.com", "127.0.0.1"))

    @mock.patch(
        "certbot_compatibility_test.validator.crypto_util.probe_sni")
    def test_certificate_failure(self, mock_probe_sni: mock.MagicMock) -> None:
        cert = crypto.X509()
        cert.set_serial_number(1337)
        mock_probe_sni.return_value = crypto.X509()
        self.assertFalse(self.validator.certificate(
            cert, "test.com", "127.0.0.1"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_successful_redirect(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            301, {"location": "https://test.com"})
        self.assertTrue(self.validator.redirect("test.com"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_redirect_with_headers(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            301, {"location": "https://test.com"})
        self.assertTrue(self.validator.redirect(
            "test.com", headers={"Host": "test.com"}))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_redirect_missing_location(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(301)
        self.assertFalse(self.validator.redirect("test.com"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_redirect_wrong_status_code(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            201, {"location": "https://test.com"})
        self.assertFalse(self.validator.redirect("test.com"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_redirect_wrong_redirect_code(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            303, {"location": "https://test.com"})
        self.assertFalse(self.validator.redirect("test.com"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_hsts_empty(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": ""})
        self.assertFalse(self.validator.hsts("test.com"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_hsts_malformed(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": "sdfal"})
        self.assertFalse(self.validator.hsts("test.com"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_hsts_bad_max_age(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": "max-age=not-an-int"})
        self.assertFalse(self.validator.hsts("test.com"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_hsts_expire(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": "max-age=3600"})
        self.assertFalse(self.validator.hsts("test.com"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_hsts(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security": "max-age=31536000"})
        self.assertTrue(self.validator.hsts("test.com"))

    @mock.patch("certbot_compatibility_test.validator.requests.get")
    def test_hsts_include_subdomains(self, mock_get_request: mock.MagicMock) -> None:
        mock_get_request.return_value = create_response(
            headers={"strict-transport-security":
                     "max-age=31536000;includeSubDomains"})
        self.assertTrue(self.validator.hsts("test.com"))

    def test_ocsp_stapling(self) -> None:
        self.assertRaises(
            NotImplementedError, self.validator.ocsp_stapling, "test.com")


def create_response(status_code: int = 200,
                    headers: Optional[Mapping[str, str]] = None) -> requests.Response:
    """Creates a requests.Response object for testing"""
    response = requests.Response()
    response.status_code = status_code

    if headers:
        response.headers = cast(requests.models.CaseInsensitiveDict, headers)

    return response


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
