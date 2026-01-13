"""Tests for certbot._internal.plugins.apache.obj."""
import sys
import unittest

import pytest


class VirtualHostTest(unittest.TestCase):
    """Test the VirtualHost class."""

    def setUp(self):
        from certbot._internal.plugins.apache.obj import Addr
        from certbot._internal.plugins.apache.obj import VirtualHost

        self.addr1 = Addr.fromstring("127.0.0.1")
        self.addr2 = Addr.fromstring("127.0.0.1:443")
        self.addr_default = Addr.fromstring("_default_:443")

        self.vhost1 = VirtualHost(
            "filep", "vh_path", {self.addr1}, False, False, "localhost")

        self.vhost1b = VirtualHost(
            "filep", "vh_path", {self.addr1}, False, False, "localhost")

        self.vhost2 = VirtualHost(
            "fp", "vhp", {self.addr2}, False, False, "localhost")

    def test_repr(self):
        assert repr(self.addr2) == \
            "certbot._internal.plugins.apache.obj.Addr(('127.0.0.1', '443'))"

    def test_eq(self):
        assert self.vhost1b == self.vhost1
        assert self.vhost1 != self.vhost2
        assert str(self.vhost1b) == str(self.vhost1)
        assert self.vhost1b != 1234

    def test_ne(self):
        assert self.vhost1 != self.vhost2
        assert self.vhost1 == self.vhost1b

    def test_conflicts(self):
        from certbot._internal.plugins.apache.obj import Addr
        from certbot._internal.plugins.apache.obj import VirtualHost

        complex_vh = VirtualHost(
            "fp", "vhp",
            {Addr.fromstring("*:443"), Addr.fromstring("1.2.3.4:443")},
            False, False)
        assert complex_vh.conflicts([self.addr1]) is True
        assert complex_vh.conflicts([self.addr2]) is True
        assert complex_vh.conflicts([self.addr_default]) is False

        assert self.vhost1.conflicts([self.addr2]) is True
        assert self.vhost1.conflicts([self.addr_default]) is False

        assert self.vhost2.conflicts([self.addr1, self.addr_default]) is False

    def test_same_server(self):
        from certbot._internal.plugins.apache.obj import VirtualHost
        no_name1 = VirtualHost(
            "fp", "vhp", {self.addr1}, False, False, None)
        no_name2 = VirtualHost(
            "fp", "vhp", {self.addr2}, False, False, None)
        no_name3 = VirtualHost(
            "fp", "vhp", {self.addr_default},
            False, False, None)
        no_name4 = VirtualHost(
            "fp", "vhp", {self.addr2, self.addr_default},
            False, False, None)

        assert self.vhost1.same_server(self.vhost2) is True
        assert no_name1.same_server(no_name2) is True

        assert self.vhost1.same_server(no_name1) is False
        assert no_name1.same_server(no_name3) is False
        assert no_name1.same_server(no_name4) is False


class AddrTest(unittest.TestCase):
    """Test obj.Addr."""
    def setUp(self):
        from certbot._internal.plugins.apache.obj import Addr
        self.addr = Addr.fromstring("*:443")

        self.addr1 = Addr.fromstring("127.0.0.1")
        self.addr2 = Addr.fromstring("127.0.0.1:*")

        self.addr_defined = Addr.fromstring("127.0.0.1:443")
        self.addr_default = Addr.fromstring("_default_:443")

    def test_wildcard(self):
        assert self.addr.is_wildcard() is False
        assert self.addr1.is_wildcard() is True
        assert self.addr2.is_wildcard() is True

    def test_get_sni_addr(self):
        from certbot._internal.plugins.apache.obj import Addr
        assert self.addr.get_sni_addr("443") == Addr.fromstring("*:443")
        assert self.addr.get_sni_addr("225") == Addr.fromstring("*:225")
        assert self.addr1.get_sni_addr("443") == Addr.fromstring("127.0.0.1")

    def test_conflicts(self):
        # Note: Defined IP is more important than defined port in match
        assert self.addr.conflicts(self.addr1) is True
        assert self.addr.conflicts(self.addr2) is True
        assert self.addr.conflicts(self.addr_defined) is True
        assert self.addr.conflicts(self.addr_default) is False

        assert self.addr1.conflicts(self.addr) is False
        assert self.addr1.conflicts(self.addr_defined) is True
        assert self.addr1.conflicts(self.addr_default) is False

        assert self.addr_defined.conflicts(self.addr1) is False
        assert self.addr_defined.conflicts(self.addr2) is False
        assert self.addr_defined.conflicts(self.addr) is False
        assert self.addr_defined.conflicts(self.addr_default) is False

        assert self.addr_default.conflicts(self.addr) is True
        assert self.addr_default.conflicts(self.addr1) is True
        assert self.addr_default.conflicts(self.addr_defined) is True

        # Self test
        assert self.addr.conflicts(self.addr) is True
        assert self.addr1.conflicts(self.addr1) is True
        # This is a tricky one...
        assert self.addr1.conflicts(self.addr2) is True

    def test_equal(self):
        assert self.addr1 == self.addr2
        assert self.addr != self.addr1
        assert self.addr != 123

    def test_not_equal(self):
        assert self.addr1 == self.addr2
        assert self.addr != self.addr1


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
