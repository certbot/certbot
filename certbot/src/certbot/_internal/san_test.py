"""Tests for the san module"""
import pytest
import unittest

from certbot._internal import san

class SanTest(unittest.TestCase):
    def test_str(self) -> None:
        assert str(san.DNSName("example.com")) == "example.com"
        assert str(san.IPAddress("192.168.1.1")) == "192.168.1.1"

    def test_hash(self) -> None:
        assert hash(san.DNSName("example.com")) == hash(san.DNSName("example.com"))
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
