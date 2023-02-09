"""Tests for certbot_apache._internal.obj."""
import sys
import unittest

import pytest


class VirtualHostTest(unittest.TestCase):
    """Test the VirtualHost class."""

    def setUp(self):
        from certbot_apache._internal.obj import Addr
        from certbot_apache._internal.obj import VirtualHost

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
        self.assertEqual(repr(self.addr2),
            "certbot_apache._internal.obj.Addr(('127.0.0.1', '443'))")

    def test_eq(self):
        self.assertEqual(self.vhost1b, self.vhost1)
        self.assertNotEqual(self.vhost1, self.vhost2)
        self.assertEqual(str(self.vhost1b), str(self.vhost1))
        self.assertNotEqual(self.vhost1b, 1234)

    def test_ne(self):
        self.assertNotEqual(self.vhost1, self.vhost2)
        self.assertEqual(self.vhost1, self.vhost1b)

    def test_conflicts(self):
        from certbot_apache._internal.obj import Addr
        from certbot_apache._internal.obj import VirtualHost

        complex_vh = VirtualHost(
            "fp", "vhp",
            {Addr.fromstring("*:443"), Addr.fromstring("1.2.3.4:443")},
            False, False)
        self.assertIs(complex_vh.conflicts([self.addr1]), True)
        self.assertIs(complex_vh.conflicts([self.addr2]), True)
        self.assertIs(complex_vh.conflicts([self.addr_default]), False)

        self.assertIs(self.vhost1.conflicts([self.addr2]), True)
        self.assertIs(self.vhost1.conflicts([self.addr_default]), False)

        self.assertIs(self.vhost2.conflicts([self.addr1, self.addr_default]), False)

    def test_same_server(self):
        from certbot_apache._internal.obj import VirtualHost
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

        self.assertIs(self.vhost1.same_server(self.vhost2), True)
        self.assertIs(no_name1.same_server(no_name2), True)

        self.assertIs(self.vhost1.same_server(no_name1), False)
        self.assertIs(no_name1.same_server(no_name3), False)
        self.assertIs(no_name1.same_server(no_name4), False)


class AddrTest(unittest.TestCase):
    """Test obj.Addr."""
    def setUp(self):
        from certbot_apache._internal.obj import Addr
        self.addr = Addr.fromstring("*:443")

        self.addr1 = Addr.fromstring("127.0.0.1")
        self.addr2 = Addr.fromstring("127.0.0.1:*")

        self.addr_defined = Addr.fromstring("127.0.0.1:443")
        self.addr_default = Addr.fromstring("_default_:443")

    def test_wildcard(self):
        self.assertIs(self.addr.is_wildcard(), False)
        self.assertIs(self.addr1.is_wildcard(), True)
        self.assertIs(self.addr2.is_wildcard(), True)

    def test_get_sni_addr(self):
        from certbot_apache._internal.obj import Addr
        self.assertEqual(
            self.addr.get_sni_addr("443"), Addr.fromstring("*:443"))
        self.assertEqual(
            self.addr.get_sni_addr("225"), Addr.fromstring("*:225"))
        self.assertEqual(
            self.addr1.get_sni_addr("443"), Addr.fromstring("127.0.0.1"))

    def test_conflicts(self):
        # Note: Defined IP is more important than defined port in match
        self.assertIs(self.addr.conflicts(self.addr1), True)
        self.assertIs(self.addr.conflicts(self.addr2), True)
        self.assertIs(self.addr.conflicts(self.addr_defined), True)
        self.assertIs(self.addr.conflicts(self.addr_default), False)

        self.assertIs(self.addr1.conflicts(self.addr), False)
        self.assertIs(self.addr1.conflicts(self.addr_defined), True)
        self.assertIs(self.addr1.conflicts(self.addr_default), False)

        self.assertIs(self.addr_defined.conflicts(self.addr1), False)
        self.assertIs(self.addr_defined.conflicts(self.addr2), False)
        self.assertIs(self.addr_defined.conflicts(self.addr), False)
        self.assertIs(self.addr_defined.conflicts(self.addr_default), False)

        self.assertIs(self.addr_default.conflicts(self.addr), True)
        self.assertIs(self.addr_default.conflicts(self.addr1), True)
        self.assertIs(self.addr_default.conflicts(self.addr_defined), True)

        # Self test
        self.assertIs(self.addr.conflicts(self.addr), True)
        self.assertIs(self.addr1.conflicts(self.addr1), True)
        # This is a tricky one...
        self.assertIs(self.addr1.conflicts(self.addr2), True)

    def test_equal(self):
        self.assertEqual(self.addr1, self.addr2)
        self.assertNotEqual(self.addr, self.addr1)
        self.assertNotEqual(self.addr, 123)

    def test_not_equal(self):
        self.assertEqual(self.addr1, self.addr2)
        self.assertNotEqual(self.addr, self.addr1)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))  # pragma: no cover
