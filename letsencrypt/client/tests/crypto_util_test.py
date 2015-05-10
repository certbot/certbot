"""Tests for letsencrypt.client.crypto_util."""
import logging
import os
import pkg_resources
import shutil
import tempfile
import unittest

import M2Crypto
import mock


RSA256_KEY = pkg_resources.resource_string(
    'letsencrypt.acme.jose', os.path.join('testdata', 'rsa256_key.pem'))
RSA512_KEY = pkg_resources.resource_string(
    'letsencrypt.acme.jose', os.path.join('testdata', 'rsa512_key.pem'))


class InitSaveKeyTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.init_save_key."""
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.key_dir = tempfile.mkdtemp('key_dir')

    def tearDown(self):
        logging.disable(logging.NOTSET)
        shutil.rmtree(self.key_dir)

    @classmethod
    def _call(cls, key_size, key_dir):
        from letsencrypt.client.crypto_util import init_save_key
        return init_save_key(key_size, key_dir, 'key-letsencrypt.pem')

    @mock.patch('letsencrypt.client.crypto_util.make_key')
    def test_success(self, mock_make):
        mock_make.return_value = 'key_pem'
        key = self._call(1024, self.key_dir)
        self.assertEqual(key.pem, 'key_pem')
        self.assertTrue('key-letsencrypt.pem' in key.file)

    @mock.patch('letsencrypt.client.crypto_util.make_key')
    def test_key_failure(self, mock_make):
        mock_make.side_effect = ValueError
        self.assertRaises(ValueError, self._call, 431, self.key_dir)


class InitSaveCSRTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.init_save_csr."""

    def setUp(self):
        self.csr_dir = tempfile.mkdtemp('csr_dir')

    def tearDown(self):
        shutil.rmtree(self.csr_dir)

    @mock.patch('letsencrypt.client.crypto_util.make_csr')
    @mock.patch('letsencrypt.client.crypto_util.le_util.make_or_verify_dir')
    def test_it(self, unused_mock_verify, mock_csr):
        from letsencrypt.client.crypto_util import init_save_csr

        mock_csr.return_value = ('csr_pem', 'csr_der')

        csr = init_save_csr(
            mock.Mock(pem='dummy_key'), 'example.com', self.csr_dir,
            'csr-letsencrypt.pem')

        self.assertEqual(csr.data, 'csr_der')
        self.assertTrue('csr-letsencrypt.pem' in csr.file)

class ValidCSRTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.valid_csr."""

    @classmethod
    def _call(cls, csr):
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


class CSRMatchesPubkeyTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.csr_matches_pubkey."""

    @classmethod
    def _call_testdata(cls, name, privkey):
        from letsencrypt.client.crypto_util import csr_matches_pubkey
        return csr_matches_pubkey(pkg_resources.resource_string(
            __name__, os.path.join('testdata', name)), privkey)

    def test_valid_true(self):
        self.assertTrue(self._call_testdata('csr.pem', RSA512_KEY))

    def test_invalid_false(self):
        self.assertFalse(self._call_testdata('csr.pem', RSA256_KEY))


class MakeKeyTest(unittest.TestCase):  # pylint: disable=too-few-public-methods
    """Tests for letsencrypt.client.crypto_util.make_key."""

    def test_it(self):  # pylint: disable=no-self-use
        from letsencrypt.client.crypto_util import make_key
        # Do not test larger keys as it takes too long.
        M2Crypto.RSA.load_key_string(make_key(1024))


class ValidPrivkeyTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.valid_privkey."""

    @classmethod
    def _call(cls, privkey):
        from letsencrypt.client.crypto_util import valid_privkey
        return valid_privkey(privkey)

    def test_valid_true(self):
        self.assertTrue(self._call(RSA256_KEY))

    def test_empty_false(self):
        self.assertFalse(self._call(''))

    def test_random_false(self):
        self.assertFalse(self._call('foo bar'))


class MakeSSCertTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods
    """Tests for letsencrypt.client.crypto_util.make_ss_cert."""

    def test_it(self):  # pylint: disable=no-self-use
        from letsencrypt.client.crypto_util import make_ss_cert
        make_ss_cert(RSA512_KEY, ['example.com', 'www.example.com'])


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
