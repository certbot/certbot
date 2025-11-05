"""Tests for the san module"""
import ipaddress
from datetime import datetime

import pytest
import unittest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from certbot import errors
from certbot._internal import san

class SanTest(unittest.TestCase):
    def test_str(self) -> None:
        assert str(san.DNSName("example.com")) == "example.com"
        assert str(san.IPAddress("192.168.1.1")) == "192.168.1.1"

    def test_hash(self) -> None:
        assert hash(san.DNSName("example.com")) == hash(san.DNSName("example.com"))
        assert hash(san.DNSName("EXAMPLE.COM.")) == hash(san.DNSName("example.com"))
        assert hash(san.IPAddress("192.168.1.1")) == hash(san.IPAddress("192.168.1.1"))

    def test_repr(self) -> None:
        assert repr(san.DNSName("example.com")) == "DNS(example.com)"
        assert repr(san.IPAddress("192.168.1.1")) == "IP(192.168.1.1)"

    def test_eq(self) -> None:
        with pytest.raises(TypeError):
            san.DNSName("example.com") == "example.com" # pylint: disable=expression-not-assigned
        with pytest.raises(TypeError):
            "example.com" == san.DNSName("example.com") # pylint: disable=expression-not-assigned
        with pytest.raises(TypeError):
            san.IPAddress("192.168.1.1") == "192.168.1.1" # pylint: disable=expression-not-assigned
        with pytest.raises(TypeError):
            "192.168.1.1" == san.IPAddress("192.168.1.1") # pylint: disable=expression-not-assigned
        assert san.DNSName("example.com") == san.DNSName("example.com")
        assert san.DNSName("Example.com") == san.DNSName("example.com")
        assert san.DNSName("example.com") == san.DNSName("Example.com")
        assert san.DNSName("EXAMPLE.COM") == san.DNSName("Example.com")
        assert san.DNSName("EXAMPLE.COM.") == san.DNSName("example.com")

    def test_is_wildcard(self) -> None:
        assert not san.DNSName("example.com").is_wildcard()
        assert not san.DNSName("example.*.com").is_wildcard()
        assert san.DNSName("*.example.com").is_wildcard()
        assert not san.IPAddress("192.168.1.1").is_wildcard()

    def test_split(self) -> None:
        assert san.split([]) == ([], [])
        assert san.split([san.IPAddress("192.168.1.1")]) == ([], [san.IPAddress("192.168.1.1")])
        assert san.split([san.DNSName("example.com")]) == ([san.DNSName("example.com")], [])
        assert san.split([san.DNSName("example.com"), san.IPAddress("192.168.1.1"),
                          san.DNSName("example.org"), san.IPAddress("192.168.1.2")]) == (
                          [san.DNSName("example.com"), san.DNSName("example.org")],
                          [san.IPAddress("192.168.1.1"), san.IPAddress("192.168.1.2")])

    def test_display(self) -> None:
        assert san.display([san.DNSName("example.com")]) == "example.com"
        assert san.display([san.DNSName("example.com"), san.IPAddress("192.168.1.1")]) \
            == "example.com, 192.168.1.1"

    def test_ip_address(self) -> None:
        with pytest.raises(ValueError):
            san.IPAddress("example.com")

class EnforceDomainSyntaxTest(unittest.TestCase):
    """Test validation of domain names."""
    def _call(self, dns_name: str) -> None:
        san.DNSName(dns_name)

    def test_nonascii_str(self) -> None:
        with pytest.raises(errors.ConfigurationError):
            self._call("eichh\u00f6rnchen.example.com")

    def test_too_long(self) -> None:
        long_domain = "a"*256
        with pytest.raises(errors.ConfigurationError):
            self._call(long_domain)

    def test_not_too_long(self) -> None:
        not_too_long_domain = "{0}.{1}.{2}.{3}".format("a"*63, "b"*63, "c"*63, "d"*63)
        self._call(not_too_long_domain)

    def test_empty_label(self) -> None:
        empty_label_domain = "fizz..example.com"
        with pytest.raises(errors.ConfigurationError):
            self._call(empty_label_domain)

    def test_empty_trailing_label(self) -> None:
        empty_trailing_label_domain = "example.com.."
        with pytest.raises(errors.ConfigurationError):
            self._call(empty_trailing_label_domain)

    def test_long_label_1(self) -> None:
        long_label_domain = "a"*64
        with pytest.raises(errors.ConfigurationError):
            self._call(long_label_domain)

    def test_long_label_2(self) -> None:
        long_label_domain = "{0}.{1}.com".format("a"*64, "b"*63)
        with pytest.raises(errors.ConfigurationError):
            self._call(long_label_domain)

    def test_not_long_label(self) -> None:
        not_too_long_label_domain = "{0}.{1}.com".format("a"*63, "b"*63)
        self._call(not_too_long_label_domain)

    def test_empty_domain(self) -> None:
        empty_domain = ""
        with pytest.raises(errors.ConfigurationError):
            self._call(empty_domain)

    def test_punycode_ok(self) -> None:
        # Punycode is now legal, so no longer an error; instead check
        # that it's _not_ an error (at the initial sanity check stage)
        self._call('this.is.xn--ls8h.tld')

class FromX509Test(unittest.TestCase):
    def test_csr(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("example.com"),
                     x509.IPAddress(ipaddress.ip_address("192.168.1.1"))]
                ),
                critical=False,
            )
        ).sign(key, hashes.SHA256())
        result = san.from_x509(csr.subject, csr.extensions)
        assert result == (
            [san.DNSName("example.com")],
            [san.IPAddress("192.168.1.1")],
        )

    def test_cert(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now())
            .subject_name(x509.Name([]))
            .issuer_name(x509.Name([]))
            .public_key(key.public_key())
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("example.com"),
                     x509.IPAddress(ipaddress.ip_address("192.168.1.1"))]
                ),
                critical=False,
            )
        ).sign(key, hashes.SHA256())
        result = san.from_x509(cert.subject, cert.extensions)
        assert result == (
            [san.DNSName("example.com")],
            [san.IPAddress("192.168.1.1")],
        )

    def test_cn(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "common.example"),
            ]))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("example.com"),
                     x509.IPAddress(ipaddress.ip_address("192.168.1.1"))]
                ),
                critical=False,
            )
        ).sign(key, hashes.SHA256())
        result = san.from_x509(csr.subject, csr.extensions)
        assert result == (
            [san.DNSName("common.example"), san.DNSName("example.com")],
            [san.IPAddress("192.168.1.1")],
        )

    def test_cn_duplicate(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
            ]))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("example.com"),
                     x509.IPAddress(ipaddress.ip_address("192.168.1.1"))]
                ),
                critical=False,
            )
        ).sign(key, hashes.SHA256())
        result = san.from_x509(csr.subject, csr.extensions)
        assert result == (
            [san.DNSName("example.com")],
            [san.IPAddress("192.168.1.1")],
        )
