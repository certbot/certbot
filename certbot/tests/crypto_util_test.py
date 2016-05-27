"""Tests for certbot.crypto_util."""
import logging
import shutil
import tempfile
import unittest

import OpenSSL
import mock
import zope.component

from certbot import errors
from certbot import interfaces
from certbot import util
from certbot.tests import test_util


RSA256_KEY = test_util.load_vector('rsa256_key.pem')
RSA512_KEY = test_util.load_vector('rsa512_key.pem')
CERT_PATH = test_util.vector_path('cert.pem')
CERT = test_util.load_vector('cert.pem')
SAN_CERT = test_util.load_vector('cert-san.pem')


class InitSaveKeyTest(unittest.TestCase):
    """Tests for certbot.crypto_util.init_save_key."""
    def setUp(self):
        logging.disable(logging.CRITICAL)
        zope.component.provideUtility(
            mock.Mock(strict_permissions=True), interfaces.IConfig)
        self.key_dir = tempfile.mkdtemp('key_dir')

    def tearDown(self):
        logging.disable(logging.NOTSET)
        shutil.rmtree(self.key_dir)

    @classmethod
    def _call(cls, key_size, key_dir):
        from certbot.crypto_util import init_save_key
        return init_save_key(key_size, key_dir, 'key-certbot.pem')

    @mock.patch('certbot.crypto_util.make_key')
    def test_success(self, mock_make):
        mock_make.return_value = 'key_pem'
        key = self._call(1024, self.key_dir)
        self.assertEqual(key.pem, 'key_pem')
        self.assertTrue('key-certbot.pem' in key.file)

    @mock.patch('certbot.crypto_util.make_key')
    def test_key_failure(self, mock_make):
        mock_make.side_effect = ValueError
        self.assertRaises(ValueError, self._call, 431, self.key_dir)


class InitSaveCSRTest(unittest.TestCase):
    """Tests for certbot.crypto_util.init_save_csr."""

    def setUp(self):
        zope.component.provideUtility(
            mock.Mock(strict_permissions=True), interfaces.IConfig)
        self.csr_dir = tempfile.mkdtemp('csr_dir')

    def tearDown(self):
        shutil.rmtree(self.csr_dir)

    @mock.patch('certbot.crypto_util.make_csr')
    @mock.patch('certbot.crypto_util.util.make_or_verify_dir')
    def test_it(self, unused_mock_verify, mock_csr):
        from certbot.crypto_util import init_save_csr

        mock_csr.return_value = ('csr_pem', 'csr_der')

        csr = init_save_csr(
            mock.Mock(pem='dummy_key'), 'example.com', self.csr_dir,
            'csr-certbot.pem')

        self.assertEqual(csr.data, 'csr_der')
        self.assertTrue('csr-certbot.pem' in csr.file)


class MakeCSRTest(unittest.TestCase):
    """Tests for certbot.crypto_util.make_csr."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import make_csr
        return make_csr(*args, **kwargs)

    def test_san(self):
        from certbot.crypto_util import get_sans_from_csr
        # TODO: Fails for RSA256_KEY
        csr_pem, csr_der = self._call(
            RSA512_KEY, ['example.com', 'www.example.com'])
        self.assertEqual(
            ['example.com', 'www.example.com'], get_sans_from_csr(csr_pem))
        self.assertEqual(
            ['example.com', 'www.example.com'], get_sans_from_csr(
                csr_der, OpenSSL.crypto.FILETYPE_ASN1))

    def test_must_staple(self):
        # TODO: Fails for RSA256_KEY
        csr_pem, _ = self._call(
            RSA512_KEY, ['example.com', 'www.example.com'], must_staple=True)
        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, csr_pem)

        # In pyopenssl 0.13 (used with TOXENV=py26-oldest and py27-oldest), csr
        # objects don't have a get_extensions() method, so we skip this test if
        # the method isn't available.
        if hasattr(csr, 'get_extensions'):
            # NOTE: Ideally we would filter by the TLS Feature OID, but
            # OpenSSL.crypto.X509Extension doesn't give us the extension's raw OID,
            # and the shortname field is just "UNDEF"
            must_staple_exts = [e for e in csr.get_extensions()
                if e.get_data() == "0\x03\x02\x01\x05"]
            self.assertEqual(len(must_staple_exts), 1,
                "Expected exactly one Must Staple extension")


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

    def test_valid_der_san_false(self):
        self.assertFalse(self._call(test_util.load_vector('csr-san.der')))

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

        self.assertEqual(
            (OpenSSL.crypto.FILETYPE_ASN1,
             util.CSR(file=csrfile,
                      data=data,
                      form="der"),
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


class GetSANsFromCSRTest(unittest.TestCase):
    """Tests for certbot.crypto_util.get_sans_from_csr."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import get_sans_from_csr
        return get_sans_from_csr(*args, **kwargs)

    def test_extract_one_san(self):
        self.assertEqual(['example.com'], self._call(
            test_util.load_vector('csr.pem')))

    def test_extract_two_sans(self):
        self.assertEqual(['example.com', 'www.example.com'], self._call(
            test_util.load_vector('csr-san.pem')))

    def test_extract_six_sans(self):
        self.assertEqual(self._call(test_util.load_vector('csr-6sans.pem')),
                         ["example.com", "example.org", "example.net",
                          "example.info", "subdomain.example.com",
                          "other.subdomain.example.com"])

    def test_parse_non_csr(self):
        self.assertRaises(OpenSSL.crypto.Error, self._call, "hello there")

    def test_parse_no_sans(self):
        self.assertEqual(
            [], self._call(test_util.load_vector('csr-nosans.pem')))


class GetNamesFromCSRTest(unittest.TestCase):
    """Tests for certbot.crypto_util.get_names_from_csr."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.crypto_util import get_names_from_csr
        return get_names_from_csr(*args, **kwargs)

    def test_extract_one_san(self):
        self.assertEqual(['example.com'], self._call(
            test_util.load_vector('csr.pem')))

    def test_extract_two_sans(self):
        self.assertEqual(set(('example.com', 'www.example.com',)), set(
            self._call(test_util.load_vector('csr-san.pem'))))

    def test_extract_six_sans(self):
        self.assertEqual(
            set(self._call(test_util.load_vector('csr-6sans.pem'))),
            set(("example.com", "example.org", "example.net",
                 "example.info", "subdomain.example.com",
                 "other.subdomain.example.com",)))

    def test_parse_non_csr(self):
        self.assertRaises(OpenSSL.crypto.Error, self._call, "hello there")

    def test_parse_no_sans(self):
        self.assertEqual(["example.org"],
                         self._call(test_util.load_vector('csr-nosans.pem')))


class CertLoaderTest(unittest.TestCase):
    """Tests for certbot.crypto_util.pyopenssl_load_certificate"""

    def test_load_valid_cert(self):
        from certbot.crypto_util import pyopenssl_load_certificate

        cert, file_type = pyopenssl_load_certificate(CERT)
        self.assertEqual(cert.digest('sha1'),
                         OpenSSL.crypto.load_certificate(file_type, CERT).digest('sha1'))

    def test_load_invalid_cert(self):
        from certbot.crypto_util import pyopenssl_load_certificate
        bad_cert_data = CERT.replace("BEGIN CERTIFICATE", "ASDFASDFASDF!!!")
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
