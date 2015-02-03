"""Tests for challenge_util."""
import os
import pkg_resources
import re
import unittest

import M2Crypto
import mock

from letsencrypt.client import challenge_util
from letsencrypt.client import CONFIG
from letsencrypt.client import le_util


class DvsniGenCertTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods
    """Tests for letsencrypt.client.challenge_util.dvsni_gen_cert."""

    def test_standard(self):
        """Basic test for straightline code."""
        # This is a helper function that can be used for handling
        # open context managers more elegantly. It avoids dealing with
        # __enter__ and __exit__ calls.
        # http://www.voidspace.org.uk/python/mock/helpers.html#mock.mock_open
        m_open = mock.mock_open()
        with mock.patch("letsencrypt.client.challenge_util.open",
                        m_open, create=True):

            domain = "example.com"
            dvsni_r = "r_value"
            r_b64 = le_util.jose_b64encode(dvsni_r)
            pem = pkg_resources.resource_string(
                __name__, os.path.join("testdata", "rsa256_key.pem"))
            key = le_util.Key("path", pem)
            nonce = "12345ABCDE"
            s_b64 = self._call("tmp.crt", domain, r_b64, nonce, key)

            self.assertTrue(m_open.called)
            self.assertEqual(m_open.call_args[0], ("tmp.crt", 'w'))
            self.assertEqual(m_open().write.call_count, 1)

            # pylint: disable=protected-access
            ext = challenge_util._dvsni_gen_ext(
                dvsni_r, le_util.jose_b64decode(s_b64))
            self._standard_check_cert(
                m_open().write.call_args[0][0], domain, nonce, ext)

    def _standard_check_cert(self, pem, domain, nonce, ext):
        """Check the certificate fields."""
        dns_regex = r"DNS:([^, $]*)"
        cert = M2Crypto.X509.load_cert_string(pem)
        self.assertEqual(
            cert.get_subject().CN, nonce + CONFIG.INVALID_EXT)

        sans = cert.get_ext("subjectAltName").get_value()

        exp_sans = set([nonce + CONFIG.INVALID_EXT, domain, ext])
        act_sans = set(re.findall(dns_regex, sans))

        self.assertEqual(exp_sans, act_sans)

    # pylint: disable= no-self-use
    def _call(self, filepath, name, r_b64, nonce, key):
        from letsencrypt.client.challenge_util import dvsni_gen_cert
        return dvsni_gen_cert(filepath, name, r_b64, nonce, key)
