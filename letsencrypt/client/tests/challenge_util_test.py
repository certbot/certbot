"""Tests for challenge_util."""
import os
import pkg_resources
import re
import unittest

import M2Crypto

from letsencrypt.client import challenge_util
from letsencrypt.client import constants
from letsencrypt.client import le_util


class DvsniGenCertTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods
    """Tests for letsencrypt.client.challenge_util.dvsni_gen_cert."""

    def test_standard(self):
        """Basic test for straightline code."""
        domain = "example.com"
        dvsni_r = "r_value"
        r_b64 = le_util.jose_b64encode(dvsni_r)
        pem = pkg_resources.resource_string(
            __name__, os.path.join("testdata", "rsa256_key.pem"))
        key = le_util.Key("path", pem)
        nonce = "12345ABCDE"
        cert_pem, s_b64 = self._call(domain, r_b64, nonce, key)

        # pylint: disable=protected-access
        ext = challenge_util._dvsni_gen_ext(
            dvsni_r, le_util.jose_b64decode(s_b64))
        self._standard_check_cert(cert_pem, domain, nonce, ext)

    def _standard_check_cert(self, pem, domain, nonce, ext):
        """Check the certificate fields."""
        dns_regex = r"DNS:([^, $]*)"
        cert = M2Crypto.X509.load_cert_string(pem)
        self.assertEqual(
            cert.get_subject().CN, nonce + constants.DVSNI_DOMAIN_SUFFIX)

        sans = cert.get_ext("subjectAltName").get_value()

        exp_sans = set([nonce + constants.DVSNI_DOMAIN_SUFFIX, domain, ext])
        act_sans = set(re.findall(dns_regex, sans))

        self.assertEqual(exp_sans, act_sans)

    @classmethod
    def _call(cls, name, r_b64, nonce, key):
        from letsencrypt.client.challenge_util import dvsni_gen_cert
        return dvsni_gen_cert(name, r_b64, nonce, key)
