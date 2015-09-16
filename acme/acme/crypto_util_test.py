"""Tests for acme.crypto_util."""
import socket
import threading
import time
import unittest

import mock
import OpenSSL

from acme import errors
from acme import jose
from acme import test_util


class ServeProbeSNITest(unittest.TestCase):
    """Tests for acme.crypto_util._serve_sni/probe_sni."""

    def setUp(self):
        self.cert = test_util.load_cert('cert.pem')
        key = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM,
            test_util.load_vector('rsa512_key.pem'))
        # pylint: disable=protected-access
        certs = {b'foo': (key, self.cert._wrapped)}

        sock = socket.socket()
        sock.bind(('', 0))  # pick random port
        self.port = sock.getsockname()[1]

        self.server = threading.Thread(target=self._run_server, args=(certs, sock))
        self.server.start()
        time.sleep(1)  # TODO: avoid race conditions in other way

    @classmethod
    def _run_server(cls, certs, sock):
        from acme.crypto_util import _serve_sni
        # TODO: improve testing of server errors and their conditions
        try:
            return _serve_sni(
                certs, sock, accept=mock.Mock(side_effect=[True, False]))
        except errors.Error:
            pass

    def tearDown(self):
        self.server.join()

    def _probe(self, name):
        from acme.crypto_util import probe_sni
        return jose.ComparableX509(probe_sni(
            name, host='127.0.0.1', port=self.port))

    def test_probe_ok(self):
        self.assertEqual(self.cert, self._probe(b'foo'))

    def test_probe_not_recognized_name(self):
        self.assertRaises(errors.Error, self._probe, b'bar')

    # TODO: py33/py34 tox hangs forever on do_hendshake in second probe
    #def probe_connection_error(self):
    #    self._probe(b'foo')
    #    #time.sleep(1)  # TODO: avoid race conditions in other way
    #    self.assertRaises(errors.Error, self._probe, b'bar')


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
