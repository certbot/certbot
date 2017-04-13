"""Tests for certbot.crypto_util."""
import logging
import os
import unittest

import OpenSSL
import mock
import zope.component

from certbot import errors
from certbot import interfaces
from certbot import util
import certbot.tests.util as test_util


RSA256_KEY = test_util.load_vector('rsa256_key.pem')
RSA512_KEY = test_util.load_vector('rsa512_key.pem')
CERT_PATH = test_util.vector_path('cert.pem')
CERT = test_util.load_vector('cert.pem')
SAN_CERT = test_util.load_vector('cert-san.pem')


class InitSaveKeyTest(test_util.TempDirTestCase):
    """Tests for certbot.crypto_util.init_save_key."""
    def setUp(self):
        super(InitSaveKeyTest, self).setUp()

        logging.disable(logging.CRITICAL)
        zope.component.provideUtility(
            mock.Mock(strict_permissions=True, dry_run=False),
            interfaces.IConfig)

    def tearDown(self):
        super(InitSaveKeyTest, self).tearDown()

        logging.disable(logging.NOTSET)

    @classmethod
    def _call(cls, key_size, key_dir):
        from certbot.crypto_util import init_save_key
        return init_save_key(key_size, key_dir, 'key-certbot.pem')

    @mock.patch('certbot.crypto_util.make_key')
    def test_success(self, mock_make):
        mock_make.return_value = b'key_pem'
        key = self._call(1024, self.tempdir)
        self.assertEqual(key.pem, b'key_pem')
        self.assertTrue('key-certbot.pem' in key.file)
        self.assertTrue(os.path.exists(os.path.join(self.tempdir, key.file)))

    @mock.patch('certbot.crypto_util.make_key')
    def test_success_dry_run(self, mock_make):
        zope.component.provideUtility(
            mock.Mock(strict_permissions=True, dry_run=True),
            interfaces.IConfig)
        mock_make.return_value = b'key_pem'
        key = self._call(1024, self.tempdir)
        self.assertEqual(key.pem, b'key_pem')
        self.assertTrue(key.file is None)

    @mock.patch('certbot.crypto_util.make_key')
    def test_key_failure(self, mock_make):
        mock_make.side_effect = ValueError
        self.assertRaises(ValueError, self._call, 431, self.tempdir)


class InitSaveCSRTest(test_util.TempDirTestCase):
    """Tests for certbot.crypto_util.init_save_csr."""

    def setUp(self):
        super(InitSaveCSRTest, self).setUp()

        zope.component.provideUtility(
            mock.Mock(strict_permissions=True, dry_run=False),
            interfaces.IConfig)

    @mock.patch('acme.crypto_util.make_csr')
    @mock.patch('certbot.crypto_util.util.make_or_verify_dir')
    def test_success(self, unused_mock_verify, mock_csr):
        from certbot.crypto_util import init_save_csr

        mock_csr.return_value = b'csr_pem'

        csr = init_save_csr(
            mock.Mock(pem='dummy_key'), 'example.com', self.tempdir)

        self.assertEqual(csr.data, b'csr_pem')
        self.assertTrue('csr-certbot.pem' in csr.file)

    @mock.patch('acme.crypto_util.make_csr')
    @mock.patch('certbot.crypto_util.util.make_or_verify_dir')
    def test_success_dry_run(self, unused_mock_verify, mock_csr):
        from certbot.crypto_util import init_save_csr

        zope.component.provideUtility(
            mock.Mock(strict_permissions=True, dry_run=True),
            interfaces.IConfig)
        mock_csr.return_value = b'csr_pem'

        csr = init_save_csr(
            mock.Mock(pem='dummy_key'), 'example.com', self.tempdir)

        self.assertEqual(csr.data, b'csr_pem')
        self.assertTrue(csr.file is None)


class ValidCSRTest(unittest.TestCase):
    """Tests for certbot.crypto_util.valid_csr."""

    @classmethod
    def _call(cls, csr):
        from certbot.crypto_util import valid_csr
        return valid_csr(csr)

    def test_valid_pem_true(self):
        self.assertTrue(self._call(test_util.load_vector('csr.pem')))

    def test_valid_pem_san_true(self):
        self.assertTrue(self._call(test_util.load_vector('csr-san.pem')))

    def test_valid_der_false(self):
        self.assertFalse(self._call(test_util.load_vector('csr.der')))

    def test_empty_false(self):
        self.assertFalse(self._call(''))

    def test_random_false(self):
        self.assertFalse(self._call('foo bar'))


class CSRMatchesPubkeyTest(unittest.TestCase):
    """Tests for certbot.crypto_util.csr_matches_pubkey."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import csr_matches_pubkey
        return csr_matches_pubkey(*args, **kwargs)

    def test_valid_true(self):
        self.assertTrue(self._call(
            test_util.load_vector('csr.pem'), RSA512_KEY))

    def test_invalid_false(self):
        self.assertFalse(self._call(
            test_util.load_vector('csr.pem'), RSA256_KEY))


class ImportCSRFileTest(unittest.TestCase):
    """Tests for certbot.certbot_util.import_csr_file."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import import_csr_file
        return import_csr_file(*args, **kwargs)

    def test_der_csr(self):
        csrfile = test_util.vector_path('csr.der')
        data = test_util.load_vector('csr.der')
        data_pem = test_util.load_vector('csr.pem')

        self.assertEqual(
            (OpenSSL.crypto.FILETYPE_PEM,
             util.CSR(file=csrfile,
                      data=data_pem,
                      form="pem"),
             ["example.com"],),
            self._call(csrfile, data))

    def test_pem_csr(self):
        csrfile = test_util.vector_path('csr.pem')
        data = test_util.load_vector('csr.pem')

        self.assertEqual(
            (OpenSSL.crypto.FILETYPE_PEM,
             util.CSR(file=csrfile,
                      data=data,
                      form="pem"),
             ["example.com"],),
            self._call(csrfile, data))

    def test_bad_csr(self):
        self.assertRaises(errors.Error, self._call,
                          test_util.vector_path('cert.pem'),
                          test_util.load_vector('cert.pem'))


class MakeKeyTest(unittest.TestCase):  # pylint: disable=too-few-public-methods
    """Tests for certbot.crypto_util.make_key."""

    def test_it(self):  # pylint: disable=no-self-use
        from certbot.crypto_util import make_key
        # Do not test larger keys as it takes too long.
        OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, make_key(1024))


class ValidPrivkeyTest(unittest.TestCase):
    """Tests for certbot.crypto_util.valid_privkey."""

    @classmethod
    def _call(cls, privkey):
        from certbot.crypto_util import valid_privkey
        return valid_privkey(privkey)

    def test_valid_true(self):
        self.assertTrue(self._call(RSA256_KEY))

    def test_empty_false(self):
        self.assertFalse(self._call(''))

    def test_random_false(self):
        self.assertFalse(self._call('foo bar'))


class GetSANsFromCertTest(unittest.TestCase):
    """Tests for certbot.crypto_util.get_sans_from_cert."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import get_sans_from_cert
        return get_sans_from_cert(*args, **kwargs)

    def test_single(self):
        self.assertEqual([], self._call(test_util.load_vector('cert.pem')))

    def test_san(self):
        self.assertEqual(
            ['example.com', 'www.example.com'],
            self._call(test_util.load_vector('cert-san.pem')))


class GetNamesFromCertTest(unittest.TestCase):
    """Tests for certbot.crypto_util.get_names_from_cert."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import get_names_from_cert
        return get_names_from_cert(*args, **kwargs)

    def test_single(self):
        self.assertEqual(
            ['example.com'],
            self._call(test_util.load_vector('cert.pem')))

    def test_san(self):
        self.assertEqual(
            ['example.com', 'www.example.com'],
            self._call(test_util.load_vector('cert-san.pem')))

    def test_common_name_sans_order(self):
        # Tests that the common name comes first
        # followed by the SANS in alphabetical order
        self.assertEqual(
            ['example.com'] + ['{0}.example.com'.format(c) for c in 'abcd'],
            self._call(test_util.load_vector('cert-5sans.pem')))

    def test_parse_non_cert(self):
        self.assertRaises(OpenSSL.crypto.Error, self._call, "hello there")


class CertLoaderTest(unittest.TestCase):
    """Tests for certbot.crypto_util.pyopenssl_load_certificate"""

    def test_load_valid_cert(self):
        from certbot.crypto_util import pyopenssl_load_certificate

        cert, file_type = pyopenssl_load_certificate(CERT)
        self.assertEqual(cert.digest('sha256'),
                         OpenSSL.crypto.load_certificate(file_type, CERT).digest('sha256'))

    def test_load_invalid_cert(self):
        from certbot.crypto_util import pyopenssl_load_certificate
        bad_cert_data = CERT.replace(b"BEGIN CERTIFICATE", b"ASDFASDFASDF!!!")
        self.assertRaises(
            errors.Error, pyopenssl_load_certificate, bad_cert_data)


class NotBeforeTest(unittest.TestCase):
    """Tests for certbot.crypto_util.notBefore"""

    def test_notBefore(self):
        from certbot.crypto_util import notBefore
        self.assertEqual(notBefore(CERT_PATH).isoformat(),
                         '2014-12-11T22:34:45+00:00')


class NotAfterTest(unittest.TestCase):
    """Tests for certbot.crypto_util.notAfter"""

    def test_notAfter(self):
        from certbot.crypto_util import notAfter
        self.assertEqual(notAfter(CERT_PATH).isoformat(),
                         '2014-12-18T22:34:45+00:00')


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
