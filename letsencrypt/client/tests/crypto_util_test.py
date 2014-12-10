"""Tests for letsencrypt.client.crypto_util."""
import pkg_resources
import unittest


class CreateSigTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.create_sig."""

    def setUp(self):
        self.privkey = pkg_resources.resource_string(
            __name__, 'testdata/rsa256_key.pem')
        self.nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'
        self.b64nonce = '7Nbyb1lI6xPVI3Hg3aKSqQ'
        self.signature = {
            'nonce': self.b64nonce,
            'alg': 'RS256',
            'jwk': {
                'kty': 'RSA',
                'e': 'AQAB',
                'n': 'rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp5'
                     '80rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q',
            },
            'sig': 'SUPYKucUnhlTt8_sMxLiigOYdf_wlOLXPI-o7aRLTsOquVjDd6r'
                   'AX9AFJHk-bCMQPJbSzXKjG6H1IWbvxjS2Ew',
        }

    def _call(self, *args, **kwargs):
        from letsencrypt.client.crypto_util import create_sig
        return create_sig(*args, **kwargs)

    def test_it(self):
        self.assertEqual(
            self._call('message', self.privkey, self.nonce), self.signature)

    def test_random_nonce(self):
        signature = self._call('message', self.privkey)
        sig = signature.pop('sig')
        nonce = signature.pop('nonce')
        del self.signature['sig']
        del self.signature['nonce']
        self.assertEqual(signature, self.signature)

if __name__ == '__main__':
    unittest.main()
