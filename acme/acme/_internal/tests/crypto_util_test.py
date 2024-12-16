"""Tests for acme.crypto_util."""
import ipaddress
import itertools
import socket
import socketserver
import sys
import threading
import time
from typing import List
import unittest

import josepy as jose
import OpenSSL
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519

from acme import errors
from acme._internal.tests import test_util


class SSLSocketAndProbeSNITest(unittest.TestCase):
    """Tests for acme.crypto_util.SSLSocket/probe_sni."""

    def setUp(self):
        self.cert = test_util.load_comparable_cert('rsa2048_cert.pem')
        key = test_util.load_pyopenssl_private_key('rsa2048_key.pem')
        # pylint: disable=protected-access
        certs = {b'foo': (key, self.cert.wrapped)}

        from acme.crypto_util import SSLSocket

        class _TestServer(socketserver.TCPServer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.socket = SSLSocket(self.socket, certs)

        self.server = _TestServer(('', 0), socketserver.BaseRequestHandler)
        self.port = self.server.socket.getsockname()[1]
        self.server_thread = threading.Thread(
            target=self.server.handle_request)

    def tearDown(self):
        if self.server_thread.is_alive():
            # The thread may have already terminated.
            self.server_thread.join()  # pragma: no cover
        self.server.server_close()

    def _probe(self, name):
        from acme.crypto_util import probe_sni
        return jose.ComparableX509(probe_sni(
            name, host='127.0.0.1', port=self.port))

    def _start_server(self):
        self.server_thread.start()
        time.sleep(1)  # TODO: avoid race conditions in other way

    def test_probe_ok(self):
        self._start_server()
        assert self.cert == self._probe(b'foo')

    def test_probe_not_recognized_name(self):
        self._start_server()
        with pytest.raises(errors.Error):
            self._probe(b'bar')

    def test_probe_connection_error(self):
        self.server.server_close()
        original_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(1)
            with pytest.raises(errors.Error):
                self._probe(b'bar')
        finally:
            socket.setdefaulttimeout(original_timeout)


class SSLSocketTest(unittest.TestCase):
    """Tests for acme.crypto_util.SSLSocket."""

    def test_ssl_socket_invalid_arguments(self):
        from acme.crypto_util import SSLSocket
        with pytest.raises(ValueError):
            _ = SSLSocket(None, {'sni': ('key', 'cert')},
                    cert_selection=lambda _: None)
        with pytest.raises(ValueError):
            _ = SSLSocket(None)


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
        assert self._call_cert('cert-nocn.der') == \
                         ['no-common-name.badssl.com']

    def test_cert_no_sans_yes_common(self):
        assert self._call_cert('cert.pem') == ['example.com']

    def test_cert_two_sans_yes_common(self):
        assert self._call_cert('cert-san.pem') == \
                         ['example.com', 'www.example.com']


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
        chars = [chr(i) for i in itertools.chain(range(0x3c3, 0x400),
                                                 range(0x641, 0x6fc),
                                                 range(0x1820, 0x1877))]
        return [''.join(chars[i: i + 45]) + '.invalid'
                for i in range(0, len(chars), 45)]

    def _call_cert(self, name):
        return self._call(test_util.load_cert, name)

    def _call_csr(self, name):
        return self._call(test_util.load_csr, name)

    def test_cert_no_sans(self):
        assert self._call_cert('cert.pem') == []

    def test_cert_two_sans(self):
        assert self._call_cert('cert-san.pem') == \
                         ['example.com', 'www.example.com']

    def test_cert_hundred_sans(self):
        assert self._call_cert('cert-100sans.pem') == \
                         ['example{0}.com'.format(i) for i in range(1, 101)]

    def test_cert_idn_sans(self):
        assert self._call_cert('cert-idnsans.pem') == \
                         self._get_idn_names()

    def test_csr_no_sans(self):
        assert self._call_csr('csr-nosans.pem') == []

    def test_csr_one_san(self):
        assert self._call_csr('csr.pem') == ['example.com']

    def test_csr_two_sans(self):
        assert self._call_csr('csr-san.pem') == \
                         ['example.com', 'www.example.com']

    def test_csr_six_sans(self):
        assert self._call_csr('csr-6sans.pem') == \
                         ['example.com', 'example.org', 'example.net',
                          'example.info', 'subdomain.example.com',
                          'other.subdomain.example.com']

    def test_csr_hundred_sans(self):
        assert self._call_csr('csr-100sans.pem') == \
                         ['example{0}.com'.format(i) for i in range(1, 101)]

    def test_csr_idn_sans(self):
        assert self._call_csr('csr-idnsans.pem') == \
                         self._get_idn_names()

    def test_critical_san(self):
        assert self._call_cert('critical-san.pem') == \
                         ['chicago-cubs.venafi.example', 'cubs.venafi.example']


class PyOpenSSLCertOrReqSANIPTest(unittest.TestCase):
    """Test for acme.crypto_util._pyopenssl_cert_or_req_san_ip."""

    @classmethod
    def _call(cls, loader, name):
        # pylint: disable=protected-access
        from acme.crypto_util import _pyopenssl_cert_or_req_san_ip
        return _pyopenssl_cert_or_req_san_ip(loader(name))

    def _call_cert(self, name):
        return self._call(test_util.load_cert, name)

    def _call_csr(self, name):
        return self._call(test_util.load_csr, name)

    def test_cert_no_sans(self):
        assert self._call_cert('cert.pem') == []

    def test_csr_no_sans(self):
        assert self._call_csr('csr-nosans.pem') == []

    def test_cert_domain_sans(self):
        assert self._call_cert('cert-san.pem') == []

    def test_csr_domain_sans(self):
        assert self._call_csr('csr-san.pem') == []

    def test_cert_ip_two_sans(self):
        assert self._call_cert('cert-ipsans.pem') == ['192.0.2.145', '203.0.113.1']

    def test_csr_ip_two_sans(self):
        assert self._call_csr('csr-ipsans.pem') == ['192.0.2.145', '203.0.113.1']

    def test_csr_ipv6_sans(self):
        assert self._call_csr('csr-ipv6sans.pem') == \
                         ['0:0:0:0:0:0:0:1', 'A3BE:32F3:206E:C75D:956:CEE:9858:5EC5']

    def test_cert_ipv6_sans(self):
        assert self._call_cert('cert-ipv6sans.pem') == \
                         ['0:0:0:0:0:0:0:1', 'A3BE:32F3:206E:C75D:956:CEE:9858:5EC5']


class GenSsCertTest(unittest.TestCase):
    """Test for gen_ss_cert (generation of self-signed cert)."""


    def setUp(self):
        self.cert_count = 5
        self.serial_num: List[int] = []
        self.key = OpenSSL.crypto.PKey()
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    def test_sn_collisions(self):
        from acme.crypto_util import gen_ss_cert
        for _ in range(self.cert_count):
            cert = gen_ss_cert(self.key, ['dummy'], force_san=True,
                               ips=[ipaddress.ip_address("10.10.10.10")])
            self.serial_num.append(cert.get_serial_number())
        assert len(set(self.serial_num)) >= self.cert_count


    def test_no_name(self):
        from acme.crypto_util import gen_ss_cert
        with pytest.raises(AssertionError):
            gen_ss_cert(self.key, ips=[ipaddress.ip_address("1.1.1.1")])
            gen_ss_cert(self.key)


class MakeCSRTest(unittest.TestCase):
    """Test for standalone functions."""

    @classmethod
    def _call_with_key(cls, *args, **kwargs):
        privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        privkey_pem = privkey.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        from acme.crypto_util import make_csr

        return make_csr(privkey_pem, *args, **kwargs)

    def test_make_csr(self):
        csr_pem = self._call_with_key(["a.example", "b.example"])
        assert b"--BEGIN CERTIFICATE REQUEST--" in csr_pem
        assert b"--END CERTIFICATE REQUEST--" in csr_pem
        csr = x509.load_pem_x509_csr(csr_pem)

        assert len(csr.extensions) == 1
        assert list(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ) == [
            x509.DNSName("a.example"),
            x509.DNSName("b.example"),
        ]

    def test_make_csr_ip(self):
        csr_pem = self._call_with_key(
            ["a.example"],
            False,
            [ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")],
        )
        assert b"--BEGIN CERTIFICATE REQUEST--" in csr_pem
        assert b"--END CERTIFICATE REQUEST--" in csr_pem

        csr = x509.load_pem_x509_csr(csr_pem)

        assert len(csr.extensions) == 1
        assert list(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ) == [
            x509.DNSName("a.example"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ]

    def test_make_csr_must_staple(self):
        csr_pem = self._call_with_key(["a.example"], must_staple=True)
        csr = x509.load_pem_x509_csr(csr_pem)

        assert len(csr.extensions) == 2
        assert list(csr.extensions.get_extension_for_class(x509.TLSFeature).value) == [
            x509.TLSFeatureType.status_request
        ]

    def test_make_csr_without_hostname(self):
        with pytest.raises(ValueError):
            self._call_with_key()

    def test_make_csr_invalid_key_type(self):
        privkey = x25519.X25519PrivateKey.generate()
        privkey_pem = privkey.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        from acme.crypto_util import make_csr

        with pytest.raises(ValueError):
            make_csr(privkey_pem, ["a.example"])


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
        assert len(self._call(loaded)) == length

    def test_dump_pyopenssl_chain_wrapped(self):
        names = ['cert.pem', 'cert-san.pem', 'cert-idnsans.pem']
        loaded = [test_util.load_cert(name) for name in names]
        wrap_func = jose.ComparableX509
        wrapped = [wrap_func(cert) for cert in loaded]
        dump_func = OpenSSL.crypto.dump_certificate
        length = sum(len(dump_func(OpenSSL.crypto.FILETYPE_PEM, cert)) for cert in loaded)
        assert len(self._call(wrapped)) == length


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
