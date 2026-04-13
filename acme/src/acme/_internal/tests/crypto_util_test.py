"""Tests for acme.crypto_util."""
import ipaddress
import itertools
import sys
import unittest

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519

from acme._internal.tests import test_util


class MiscTests(unittest.TestCase):

    def test_dump_cryptography_chain(self):
        from acme.crypto_util import dump_cryptography_chain

        cert1 = test_util.load_cert('rsa2048_cert.pem')
        cert2 = test_util.load_cert('rsa4096_cert.pem')

        chain = [cert1, cert2]
        dumped = dump_cryptography_chain(chain)

        # default is PEM encoding Encoding.PEM
        assert isinstance(dumped, bytes)


class CryptographyCertOrReqSANTest(unittest.TestCase):
    """Test for acme.crypto_util._cryptography_cert_or_req_san."""

    @classmethod
    def _call(cls, loader, name):
        # pylint: disable=protected-access
        from acme.crypto_util import _cryptography_cert_or_req_san
        return _cryptography_cert_or_req_san(loader(name))

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


class GetNamesFromSubjectAndExtensionsTest(unittest.TestCase):
    """Test for get_names_from_subject_and_extensions."""

    @classmethod
    def _call_cert(cls, name: str):
        from acme.crypto_util import get_names_from_subject_and_extensions
        cert = test_util.load_cert(name)
        return get_names_from_subject_and_extensions(cert.subject, cert.extensions)

    @classmethod
    def _call_csr(cls, name: str):
        from acme.crypto_util import get_names_from_subject_and_extensions
        csr = test_util.load_csr(name)
        return get_names_from_subject_and_extensions(csr.subject, csr.extensions)

    def test_cert_one_cn_no_sans(self):
        assert self._call_cert('cert.pem') == ['example.com']

    def test_cert_two_sans(self):
        assert self._call_cert('cert-san.pem') == \
                         ['example.com', 'www.example.com']

    def test_cert_hundred_sans(self):
        assert self._call_cert('cert-100sans.pem') == \
                         ['example.com'] + ['example{0}.com'.format(i) for i in range(1, 101)]

    def test_csr_one_cn_no_sans(self):
        assert self._call_csr('csr-nosans.pem') == ['example.org']

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
                        ['example.com'] + ['example{0}.com'.format(i) for i in range(1, 101)]

    def test_critical_san(self):
        assert self._call_cert('critical-san.pem') == \
                         ['chicago-cubs.venafi.example', 'cubs.venafi.example']


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
