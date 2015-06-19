"""Tests for letsencrypt.achallenges."""
import unittest

import OpenSSL

from acme import challenges
from acme import crypto_util as acme_crypto_util
from acme import jose

from letsencrypt import crypto_util

from letsencrypt.tests import acme_util
from letsencrypt.tests import test_util


class DVSNITest(unittest.TestCase):
    """Tests for letsencrypt.achallenges.DVSNI."""

    def setUp(self):
        self.chall = acme_util.chall_to_challb(
            challenges.DVSNI(r="r_value", nonce="12345ABCDE"), "pending")
        self.response = challenges.DVSNIResponse()
        key = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))

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
        self.assertEqual(acme_crypto_util._pyopenssl_cert_or_req_san(cert), [
            "example.com", self.chall.nonce_domain,
            self.response.z_domain(self.chall)])


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
