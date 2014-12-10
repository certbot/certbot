"""Tests for letsencrypt.client.crypto_util."""
import os
import pkg_resources
import tempfile
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


class MakeCSRTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.make_csr."""

    def setUp(self):
        self.key = pkg_resources.resource_string(
            __name__, 'testdata/rsa256_key.pem')

    def test_single_domain(self):
        from letsencrypt.client.crypto_util import make_csr
        pem, der = make_csr(self.key, ['example.com'])
        self.assertEqual(pem, pkg_resources.resource_string(
            __name__, 'testdata/csr.pem'))
        self.assertEqual(der, pkg_resources.resource_string(
            __name__, 'testdata/csr.der'))

    def test_san(self):
        from letsencrypt.client.crypto_util import make_csr
        pem, der = make_csr(self.key, ['example.com', 'www.example.com'])
        self.assertEqual(pem, pkg_resources.resource_string(
            __name__, 'testdata/csr-san.pem'))
        self.assertEqual(der, pkg_resources.resource_string(
            __name__, 'testdata/csr-san.der'))


class ValidCSRTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.valid_csr."""

    def _call(self, csr):
        from letsencrypt.client.crypto_util import valid_csr
        return valid_csr(csr)

    def _call_testdata(self, name):
        return self._call(pkg_resources.resource_string(
            __name__, os.path.join('testdata', name)))

    def test_valid_pem_true(self):
        self.assertTrue(self._call_testdata('csr.pem'))

    def test_valid_pem_san_true(self):
        self.assertTrue(self._call_testdata('csr-san.pem'))

    def test_valid_der_false(self):
        self.assertFalse(self._call_testdata('csr.der'))

    def test_valid_der_san_false(self):
        self.assertFalse(self._call_testdata('csr-san.der'))

    def test_empty_false(self):
        self.assertFalse(self._call(''))

    def test_random_false(self):
        self.assertFalse(self._call('foo bar'))


class CSRMatchesNamesTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.csr_matches_names."""

    def _call(self, csr, domains):
        from letsencrypt.client.crypto_util import csr_matches_names
        return csr_matches_names(csr, domains)

    def _call_testdata(self, name, domains):
        return self._call(pkg_resources.resource_string(
            __name__, os.path.join('testdata', name)), domains)

    def test_it(self):
        self.assertTrue(self._call_testdata('csr.der', ['example.com']))
        self.assertFalse(self._call_testdata('csr.der', ['www.example.com']))
        self.assertFalse(self._call_testdata('csr.der', ['example']))

    def test_san(self):
        self.assertTrue(self._call_testdata('csr-san.der', ['example.com']))
        self.assertTrue(self._call_testdata('csr-san.der', ['www.example.com']))
        self.assertFalse(self._call_testdata('csr-san.der', ['example']))


class CSRMatchesPubkeyTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.csr_matches_pubkey."""

    def _call_testdata(self, name, privkey):
        from letsencrypt.client.crypto_util import csr_matches_pubkey
        return csr_matches_pubkey(pkg_resources.resource_string(
            __name__, os.path.join('testdata', name)), privkey)

    def test_valid_true(self):
        key = pkg_resources.resource_string(__name__, 'testdata/rsa256_key.pem')
        self.assertTrue(self._call_testdata('csr.pem', key))

    def test_invalid_false(self):
        key = pkg_resources.resource_string(__name__, 'testdata/rsa512_key.pem')
        self.assertFalse(self._call_testdata('csr.pem', key))


class ValidPrivkeyTest(unittest.TestCase):
    """Tests fro letsencrypt.client.crypto_util.valid_privkey."""

    def _call(self, privkey):
        from letsencrypt.client.crypto_util import valid_privkey
        return valid_privkey(privkey)

    def test_valid_true(self):
        self.assertTrue(self._call(pkg_resources.resource_string(
            __name__, 'testdata/rsa256_key.pem')))

    def test_empty_false(self):
        self.assertFalse(self._call(''))

    def test_random_false(self):
        self.assertFalse(self._call('foo bar'))


if __name__ == '__main__':
    unittest.main()
