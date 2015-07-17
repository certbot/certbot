"""Tests for letsencrypt.achallenges."""
import unittest

import mock
import OpenSSL

from acme import jose

from letsencrypt import crypto_util

from letsencrypt.tests import acme_util
from letsencrypt.tests import test_util


class DVSNITest(unittest.TestCase):
    """Tests for letsencrypt.achallenges.DVSNI."""

    def setUp(self):
        self.challb = acme_util.chall_to_challb(acme_util.DVSNI, "pending")
        account = mock.Mock(key=jose.JWKRSA.load(
            test_util.load_vector("rsa512_key.pem")))
        from letsencrypt.achallenges import DVSNI
        self.achall = DVSNI(
            challb=self.challb, domain="example.com", account=account)

    def test_proxy(self):
        self.assertEqual(self.challb.token, self.achall.token)

    def test_gen_cert_and_response(self):
        response, cert_pem, _ = self.achall.gen_cert_and_response()
        self.assertTrue(response.z_domain in crypto_util.get_sans_from_cert(
            cert_pem, typ=OpenSSL.crypto.FILETYPE_PEM))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
