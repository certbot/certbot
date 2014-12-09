"""Tests for letsencrypt.client.crypto_util."""
import unittest


class CreateSigTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.create_sig."""

    def setUp(self):
        self.privkey = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKx1c7RR7R/drnBSQ/zfx1vQLHUbFLh1AQQQ5R8DZUXd36efNK79
vukFhN9HFoHZiUvOjm0c+pVE6K+EdE/twuUCAwEAAQJAMbrEnJCrQe8YqAbw1/Bn
elAzIamndfE3U8bTavf9sgFpS4HL83rhd6PDbvx81ucaJAT/5x048fM/nFl4fzAc
mQIhAOF/a9o3EIsDKEmUl+Z1OaOiUxDF3kqWSmALEsmvDhwXAiEAw8ljV5RO/rUp
Zu2YMDFq3MKpyyMgBIJ8CxmGRc6gCmMCIGRQzkcmhfqBrhOFwkmozrqIBRIKJIjj
8TRm2LXWZZ2DAiAqVO7PztdNpynugUy4jtbGKKjBrTSNBRGA7OHlUgm0dQIhALQq
6oGU29Vxlvt3k0vmiRKU4AVfLyNXIGtcWcNG46h/
-----END RSA PRIVATE KEY-----"""
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
