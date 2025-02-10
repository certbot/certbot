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
from unittest import mock
import warnings

import OpenSSL
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519

from acme import errors
from acme._internal.tests import test_util


class FormatTest(unittest.TestCase):
    def test_to_cryptography_encoding(self):
        from acme.crypto_util import Format
        assert Format.DER.to_cryptography_encoding() == serialization.Encoding.DER
        assert Format.PEM.to_cryptography_encoding() == serialization.Encoding.PEM


class SSLSocketAndProbeSNITest(unittest.TestCase):
    """Tests for acme.crypto_util.SSLSocket/probe_sni."""

    def setUp(self):
        self.cert = test_util.load_cert('rsa2048_cert.pem')
        key = test_util.load_pyopenssl_private_key('rsa2048_key.pem')
        # pylint: disable=protected-access
        certs = {b'foo': (key, self.cert)}

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
        return probe_sni(name, host='127.0.0.1', port=self.port)

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


class GenMakeSelfSignedCertTest(unittest.TestCase):
    """Test for make_self_signed_cert."""

    def setUp(self):
        self.cert_count = 5
        self.serial_num: List[int] = []
        self.privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_sn_collisions(self):
        from acme.crypto_util import make_self_signed_cert
        for _ in range(self.cert_count):
            cert = make_self_signed_cert(self.privkey, ['dummy'], force_san=True,
                               ips=[ipaddress.ip_address("10.10.10.10")])
            self.serial_num.append(cert.serial_number)
        assert len(set(self.serial_num)) >= self.cert_count

    def test_no_ips(self):
        from acme.crypto_util import make_self_signed_cert
        cert = make_self_signed_cert(self.privkey, ['dummy'])

    @mock.patch("acme.crypto_util._now")
    def test_expiry_times(self, mock_now):
        from acme.crypto_util import make_self_signed_cert
        from datetime import datetime, timedelta, timezone
        not_before = 1736200830
        validity = 100

        not_before_dt = datetime.fromtimestamp(not_before)
        validity_td = timedelta(validity)
        not_after_dt = not_before_dt + validity_td
        cert = make_self_signed_cert(
            self.privkey,
            ['dummy'],
            not_before=not_before_dt,
            validity=validity_td,
        )
        # TODO: This should be `not_valid_before_utc` once we raise the minimum
        # cryptography version.
        # https://github.com/certbot/certbot/issues/10105
        with warnings.catch_warnings():
            warnings.filterwarnings(
                'ignore',
                message='Properties that return.*datetime object'
            )
            self.assertEqual(cert.not_valid_before, not_before_dt)
            self.assertEqual(cert.not_valid_after, not_after_dt)

        now = not_before + 1
        now_dt = datetime.fromtimestamp(now)
        mock_now.return_value = now_dt.replace(tzinfo=timezone.utc)
        valid_after_now_dt = now_dt + validity_td
        cert = make_self_signed_cert(
            self.privkey,
            ['dummy'],
            validity=validity_td,
        )
        with warnings.catch_warnings():
            warnings.filterwarnings(
                'ignore',
                message='Properties that return.*datetime object'
            )
            self.assertEqual(cert.not_valid_before, now_dt)
            self.assertEqual(cert.not_valid_after, valid_after_now_dt)

    def test_no_name(self):
        from acme.crypto_util import make_self_signed_cert
        with pytest.raises(AssertionError):
            make_self_signed_cert(self.privkey, ips=[ipaddress.ip_address("1.1.1.1")])
            make_self_signed_cert(self.privkey)

    def test_extensions(self):
        from acme.crypto_util import make_self_signed_cert
        extension_type = x509.TLSFeature([x509.TLSFeatureType.status_request])
        extension = x509.Extension(
            x509.TLSFeature.oid,
            False,
            extension_type
        )
        cert = make_self_signed_cert(
            self.privkey,
            ips=[ipaddress.ip_address("1.1.1.1")],
            extensions=[extension]
        )
        self.assertIn(extension, cert.extensions)


class GenSsCertTest(unittest.TestCase):
    """Test for gen_ss_cert (generation of self-signed cert)."""


    def setUp(self):
        self.cert_count = 5
        self.serial_num: List[int] = []
        self.key = OpenSSL.crypto.PKey()
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    def test_sn_collisions(self):
        from acme.crypto_util import gen_ss_cert
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            for _ in range(self.cert_count):
                cert = gen_ss_cert(self.key, ['dummy'], force_san=True,
                                ips=[ipaddress.ip_address("10.10.10.10")])
                self.serial_num.append(cert.get_serial_number())
            assert len(set(self.serial_num)) >= self.cert_count

    def test_no_name(self):
        from acme.crypto_util import gen_ss_cert
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with pytest.raises(AssertionError):
                gen_ss_cert(self.key, ips=[ipaddress.ip_address("1.1.1.1")])
                gen_ss_cert(self.key)

    def test_no_ips(self):
        from acme.crypto_util import gen_ss_cert
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            gen_ss_cert(self.key, ['dummy'])


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


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
