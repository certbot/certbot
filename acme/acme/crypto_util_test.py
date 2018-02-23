"""Tests for acme.crypto_util."""
import itertools
import socket
import threading
import time
import unittest

import six
from six.moves import socketserver  #type: ignore  # pylint: disable=import-error

import josepy as jose
import OpenSSL

from acme import errors
from acme import test_util


class SSLSocketAndProbeSNITest(unittest.TestCase):
    """Tests for acme.crypto_util.SSLSocket/probe_sni."""


    def setUp(self):
        self.cert = test_util.load_comparable_cert('rsa2048_cert.pem')
        key = test_util.load_pyopenssl_private_key('rsa2048_key.pem')
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

    # TODO: py33/py34 tox hangs forever on do_handshake in second probe
    #def probe_connection_error(self):
    #    self._probe(b'foo')
    #    #time.sleep(1)  # TODO: avoid race conditions in other way
    #    self.assertRaises(errors.Error, self._probe, b'bar')


class PyOpenSSLCertOrReqAllNamesTest(unittest.TestCase):
    """Test for acme.crypto_util._pyopenssl_cert_or_req_all_names."""

    @classmethod
    def _call(cls, loader, name):
        # pylint: disable=protected-access
        from acme.crypto_util import _pyopenssl_cert_or_req_all_names
        return _pyopenssl_cert_or_req_all_names(loader(name))

    def _call_cert(self, name):
        return self._call(test_util.load_cert, name)

    def test_cert_one_san_no_common(self):
        self.assertEqual(self._call_cert('cert-nocn.der'),
                         ['no-common-name.badssl.com'])

    def test_cert_no_sans_yes_common(self):
        self.assertEqual(self._call_cert('cert.pem'), ['example.com'])

    def test_cert_two_sans_yes_common(self):
        self.assertEqual(self._call_cert('cert-san.pem'),
                         ['example.com', 'www.example.com'])


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

    def test_critical_san(self):
        self.assertEqual(self._call_cert('critical-san.pem'),
                         ['chicago-cubs.venafi.example', 'cubs.venafi.example'])



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

class MakeCSRTest(unittest.TestCase):
    """Test for standalone functions."""

    @classmethod
    def _call_with_key(cls, *args, **kwargs):
        privkey = OpenSSL.crypto.PKey()
        privkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        privkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, privkey)
        from acme.crypto_util import make_csr
        return make_csr(privkey_pem, *args, **kwargs)

    def test_make_csr(self):
        csr_pem = self._call_with_key(["a.example", "b.example"])
        self.assertTrue(b'--BEGIN CERTIFICATE REQUEST--' in csr_pem)
        self.assertTrue(b'--END CERTIFICATE REQUEST--' in csr_pem)
        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, csr_pem)
        # In pyopenssl 0.13 (used with TOXENV=py27-oldest), csr objects don't
        # have a get_extensions() method, so we skip this test if the method
        # isn't available.
        if hasattr(csr, 'get_extensions'):
            self.assertEquals(len(csr.get_extensions()), 1)
            self.assertEquals(csr.get_extensions()[0].get_data(),
                OpenSSL.crypto.X509Extension(
                    b'subjectAltName',
                    critical=False,
                    value=b'DNS:a.example, DNS:b.example',
                ).get_data(),
            )

    def test_make_csr_must_staple(self):
        csr_pem = self._call_with_key(["a.example"], must_staple=True)
        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, csr_pem)

        # In pyopenssl 0.13 (used with TOXENV=py27-oldest), csr objects don't
        # have a get_extensions() method, so we skip this test if the method
        # isn't available.
        if hasattr(csr, 'get_extensions'):
            self.assertEquals(len(csr.get_extensions()), 2)
            # NOTE: Ideally we would filter by the TLS Feature OID, but
            # OpenSSL.crypto.X509Extension doesn't give us the extension's raw OID,
            # and the shortname field is just "UNDEF"
            must_staple_exts = [e for e in csr.get_extensions()
                if e.get_data() == b"0\x03\x02\x01\x05"]
            self.assertEqual(len(must_staple_exts), 1,
                "Expected exactly one Must Staple extension")


class DumpPyopensslChainTest(unittest.TestCase):
    """Test for dump_pyopenssl_chain."""

    @classmethod
    def _call(cls, loaded):
        # pylint: disable=protected-access
        from acme.crypto_util import dump_pyopenssl_chain
        return dump_pyopenssl_chain(loaded)

    def test_dump_pyopenssl_chain(self):
        names = ['cert.pem', 'cert-san.pem', 'cert-idnsans.pem']
        loaded = [test_util.load_cert(name) for name in names]
        length = sum(
            len(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            for cert in loaded)
        self.assertEqual(len(self._call(loaded)), length)

    def test_dump_pyopenssl_chain_wrapped(self):
        names = ['cert.pem', 'cert-san.pem', 'cert-idnsans.pem']
        loaded = [test_util.load_cert(name) for name in names]
        wrap_func = jose.ComparableX509
        wrapped = [wrap_func(cert) for cert in loaded]
        dump_func = OpenSSL.crypto.dump_certificate
        length = sum(len(dump_func(OpenSSL.crypto.FILETYPE_PEM, cert)) for cert in loaded)
        self.assertEqual(len(self._call(wrapped)), length)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
