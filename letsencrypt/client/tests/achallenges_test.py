"""Tests for letsencrypt.client.achallenges."""
import os
import pkg_resources
import re
import unittest

import M2Crypto
import mock

from letsencrypt.acme import challenges
from letsencrypt.client import le_util


class DVSNITest(unittest.TestCase):
    """Tests for letsencrypt.client.achallenges.DVSNI."""

    def setUp(self):
        self.chall = challenges.DVSNI(r="r_value", nonce="12345ABCDE")
        self.response = challenges.DVSNIResponse()
        key = le_util.Key("path", pkg_resources.resource_string(
            "letsencrypt.acme.jose",
            os.path.join("testdata", "rsa512_key.pem")))

        from letsencrypt.client.achallenges import DVSNI
        self.achall = DVSNI(chall=self.chall, domain="example.com", key=key)

    def test_proxy(self):
        self.assertEqual(self.chall.r, self.achall.r)
        self.assertEqual(self.chall.nonce, self.achall.nonce)

    def test_gen_cert_and_response(self):
        cert_pem, _ = self.achall.gen_cert_and_response(s=self.response.s)

        cert = M2Crypto.X509.load_cert_string(cert_pem)
        self.assertEqual(cert.get_subject().CN, self.chall.nonce_domain)

        sans = cert.get_ext("subjectAltName").get_value()
        self.assertEqual(
            set([self.chall.nonce_domain, "example.com",
                 self.response.z_domain(self.chall)]),
            set(re.findall(r"DNS:([^, $]*)", sans)),
        )


class IndexedTest(unittest.TestCase):
    """Tests for letsencrypt.client.achallenges.Indexed."""

    def setUp(self):
        from letsencrypt.client.achallenges import Indexed
        self.achall = mock.MagicMock()
        self.ichall = Indexed(achall=self.achall, index=0)

    def test_attributes(self):
        self.assertEqual(self.achall, self.ichall.achall)
        self.assertEqual(0, self.ichall.index)

    def test_proxy(self):
        self.assertEqual(self.achall.foo, self.ichall.foo)



if __name__ == "__main__":
    unittest.main()
