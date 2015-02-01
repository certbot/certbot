"""Tests for letsencrypt.acme.sig."""
import pkg_resources
import unittest

import Crypto.PublicKey.RSA

from letsencrypt.acme import jose


RSA256_KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', 'testdata/rsa256_key.pem'))
RSA512_KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', 'testdata/rsa512_key.pem'))


class SigatureTest(unittest.TestCase):
    """Tests for letsencrypt.acme.sig.Signature."""

    def setUp(self):
        self.alg = 'RS256'
        self.sig = ('IC\xd8*\xe7\x14\x9e\x19S\xb7\xcf\xec3\x12\xe2\x8a\x03'
                    '\x98u\xff\xf0\x94\xe2\xd7<\x8f\xa8\xed\xa4KN\xc3\xaa'
                    '\xb9X\xc3w\xaa\xc0_\xd0\x05$y>l#\x10<\x96\xd2\xcdr\xa3'
                    '\x1b\xa1\xf5!f\xef\xc64\xb6\x13')
        self.nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'
        self.jwk = jose.JWK(RSA256_KEY)

        self.b64sig = ('SUPYKucUnhlTt8_sMxLiigOYdf_wlOLXPI-o7aRLTsOquVjDd6r'
                       'AX9AFJHk-bCMQPJbSzXKjG6H1IWbvxjS2Ew')
        self.b64nonce = '7Nbyb1lI6xPVI3Hg3aKSqQ'
        self.jsig = {
            'nonce': self.b64nonce,
            'alg': self.alg,
            'jwk': self.jwk,
            'sig': self.b64sig,
        }

    @classmethod
    def _from_msg(cls, *args, **kwargs):
        from letsencrypt.acme.other import Signature
        return Signature.from_msg(*args, **kwargs)

    def test_from_msg(self):
        sig = self._from_msg('message', RSA256_KEY, self.nonce)
        self.assertEqual(sig.alg, self.alg)
        self.assertEqual(sig.sig, self.sig)
        self.assertEqual(sig.nonce, self.nonce)
        self.assertEqual(sig.jwk, self.jwk)

    def test_from_random_nonce(self):
        sig = self._from_msg('message', RSA256_KEY)
        self.assertEqual(sig.alg, self.alg)
        self.assertEqual(sig.jwk, self.jwk)

if __name__ == "__main__":
    unittest.main()
