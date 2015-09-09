"""Tests for letsencrypt.achallenges."""
import unittest

from acme import challenges
from acme import jose

from letsencrypt.tests import acme_util
from letsencrypt.tests import test_util


class DVSNITest(unittest.TestCase):
    """Tests for letsencrypt.achallenges.DVSNI."""

    def setUp(self):
        self.challb = acme_util.chall_to_challb(acme_util.DVSNI, "pending")
        key = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))
        from letsencrypt.achallenges import DVSNI
        self.achall = DVSNI(
            challb=self.challb, domain="example.com", account_key=key)

    def test_proxy(self):
        self.assertEqual(self.challb.token, self.achall.token)

    def test_gen_cert_and_response(self):
        response, cert_pem, key_pem = self.achall.gen_cert_and_response()
        self.assertTrue(isinstance(response, challenges.DVSNIResponse))
        self.assertTrue(isinstance(cert_pem, bytes))
        self.assertTrue(isinstance(key_pem, bytes))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
