"""Tests for the san module"""
import ipaddress
from datetime import datetime

import pytest
import unittest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

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
