"""Tests for letsencrypt.achallenges."""
import os
import pkg_resources
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import OpenSSL

from acme import challenges
from acme import jose

from letsencrypt import crypto_util
from letsencrypt.tests import acme_util


class DVSNITest(unittest.TestCase):
    """Tests for letsencrypt.achallenges.DVSNI."""

    def setUp(self):
        self.chall = acme_util.chall_to_challb(
            challenges.DVSNI(r="r_value", nonce="12345ABCDE"), "pending")
        self.response = challenges.DVSNIResponse()
        key = jose.JWKRSA(key=jose.ComparableRSAKey(
            serialization.load_pem_private_key(
                pkg_resources.resource_string(
                    "letsencrypt.tests", os.path.join(
                        "testdata", "rsa512_key.pem")),
                password=None, backend=default_backend())))

        from letsencrypt.achallenges import DVSNI
        self.achall = DVSNI(challb=self.chall, domain="example.com", key=key)

    def test_proxy(self):
        self.assertEqual(self.chall.r, self.achall.r)
        self.assertEqual(self.chall.nonce, self.achall.nonce)

    def test_gen_cert_and_response(self):
        cert_pem, _ = self.achall.gen_cert_and_response(s=self.response.s)

        cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert_pem)
        self.assertEqual(cert.get_subject().CN, "example.com")
        # pylint: disable=protected-access
        self.assertEqual(crypto_util._pyopenssl_cert_or_req_san(cert), [
            "example.com", self.chall.nonce_domain,
            self.response.z_domain(self.chall)])


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
