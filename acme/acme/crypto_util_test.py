"""Tests for acme.crypto_util."""
import itertools
import socket
import threading
import time
import unittest

import six
from six.moves import socketserver  # pylint: disable=import-error

import OpenSSL

from acme import errors
from acme import jose
from acme import test_util


class SSLSocketAndProbeSNITest(unittest.TestCase):
    """Tests for acme.crypto_util.SSLSocket/probe_sni."""

    def setUp(self):
        self.cert = test_util.load_comparable_cert('cert.pem')
        key = test_util.load_pyopenssl_private_key('rsa512_key.pem')
        # pylint: disable=protected-access
        certs = {b'foo': (key, self.cert.wrapped)}

        from acme.crypto_util import SSLSocket

        class _TestServer(socketserver.TCPServer):

            # pylint: disable=too-few-public-methods
            # six.moves.* | pylint: disable=attribute-defined-outside-init,no-init

            def server_bind(self):  # pylint: disable=missing-docstring
                self.socket = SSLSocket(socket.socket(), certs=certs)
                socketserver.TCPServer.server_bind(self)

        self.server = _TestServer(('', 0), socketserver.BaseRequestHandler)
        self.port = self.server.socket.getsockname()[1]
        self.server_thread = threading.Thread(
            # pylint: disable=no-member
            target=self.server.handle_request)
        self.server_thread.start()
        time.sleep(1)  # TODO: avoid race conditions in other way

    def tearDown(self):
        self.server_thread.join()

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

    @classmethod
    def _get_idn_names(cls):
        """Returns expected names from '{cert,csr}-idnsans.pem'."""
        chars = [six.unichr(i) for i in itertools.chain(range(0x3c3, 0x400),
                                                        range(0x641, 0x6fc),
                                                        range(0x1820, 0x1877))]
        return [''.join(chars[i: i + 45]) + '.invalid'
                for i in range(0, len(chars), 45)]

    def _call_cert(self, name):
        return self._call(test_util.load_cert, name)

    def _call_csr(self, name):
        return self._call(test_util.load_csr, name)

    def test_cert_no_sans(self):
        self.assertEqual(self._call_cert('cert.pem'), [])

    def test_cert_two_sans(self):
        self.assertEqual(self._call_cert('cert-san.pem'),
                         ['example.com', 'www.example.com'])

    def test_cert_hundred_sans(self):
        self.assertEqual(self._call_cert('cert-100sans.pem'),
                         ['example{0}.com'.format(i) for i in range(1, 101)])

    def test_cert_idn_sans(self):
        self.assertEqual(self._call_cert('cert-idnsans.pem'),
                         self._get_idn_names())

    def test_csr_no_sans(self):
        self.assertEqual(self._call_csr('csr-nosans.pem'), [])

    def test_csr_one_san(self):
        self.assertEqual(self._call_csr('csr.pem'), ['example.com'])

    def test_csr_two_sans(self):
        self.assertEqual(self._call_csr('csr-san.pem'),
                         ['example.com', 'www.example.com'])

    def test_csr_six_sans(self):
        self.assertEqual(self._call_csr('csr-6sans.pem'),
                         ['example.com', 'example.org', 'example.net',
                          'example.info', 'subdomain.example.com',
                          'other.subdomain.example.com'])

    def test_csr_hundred_sans(self):
        self.assertEqual(self._call_csr('csr-100sans.pem'),
                         ['example{0}.com'.format(i) for i in range(1, 101)])

    def test_csr_idn_sans(self):
        self.assertEqual(self._call_csr('csr-idnsans.pem'),
                         self._get_idn_names())


class RandomSnTest(unittest.TestCase):
    """Test for random certificate serial numbers."""

    def setUp(self):
        self.cert_count = 5
        self.serial_num = []
        self.key = OpenSSL.crypto.PKey()
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    def test_sn_collisions(self):
        from acme.crypto_util import gen_ss_cert

        for _ in range(self.cert_count):
            cert = gen_ss_cert(self.key, ['dummy'], force_san=True)
            self.serial_num.append(cert.get_serial_number())
        self.assertTrue(len(set(self.serial_num)) > 1)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
