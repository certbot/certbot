"""Tests for acme.crypto_util."""
import socket
import unittest

import OpenSSL

from acme import test_util


class ProbeSNITest(unittest.TestCase):
    """Tests for acme.crypto_util._probe_sni."""

    def test_it(self):
        from acme.crypto_util import _probe_sni
        # TODO: mock this out
        cert = _probe_sni(
            "google.com", socket.gethostbyname("google.com"), port=443)
        self.assertTrue(isinstance(cert, OpenSSL.crypto.X509))


class PyOpenSSLCertOrReqSANTest(unittest.TestCase):
    """Test for acme.crypto_util._pyopenssl_cert_or_req_san."""

    @classmethod
    def _call(cls, loader, name):
        # pylint: disable=protected-access
        from acme.crypto_util import _pyopenssl_cert_or_req_san
        return _pyopenssl_cert_or_req_san(loader(name))

    def _call_cert(self, name):
        return self._call(test_util.load_cert, name)

    def _call_csr(self, name):
        return self._call(test_util.load_csr, name)

    def test_cert_no_sans(self):
        self.assertEqual(self._call_cert('cert.pem'), [])

    def test_cert_two_sans(self):
        self.assertEqual(self._call_cert('cert-san.pem'),
                         ['example.com', 'www.example.com'])

    def test_csr_no_sans(self):
        self.assertEqual(self._call_csr('csr-nosans.pem'), [])

    def test_csr_one_san(self):
        self.assertEqual(self._call_csr('csr.pem'), ['example.com'])

    def test_csr_two_sans(self):
        self.assertEqual(self._call_csr('csr-san.pem'),
                         ['example.com', 'www.example.com'])

    def test_csr_six_sans(self):
        self.assertEqual(self._call_csr('csr-6sans.pem'),
                         ["example.com", "example.org", "example.net",
                          "example.info", "subdomain.example.com",
                          "other.subdomain.example.com"])


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
