"""Tests for certbot_apache._internal.obj."""
import unittest


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
        self.assertTrue(self.vhost1b == self.vhost1)
        self.assertFalse(self.vhost1 == self.vhost2)
        self.assertEqual(str(self.vhost1b), str(self.vhost1))
        self.assertFalse(self.vhost1b == 1234)

    def test_ne(self):
        self.assertTrue(self.vhost1 != self.vhost2)
        self.assertFalse(self.vhost1 != self.vhost1b)

    def test_conflicts(self):
        from certbot_apache._internal.obj import Addr
        from certbot_apache._internal.obj import VirtualHost

        complex_vh = VirtualHost(
            "fp", "vhp",
            {Addr.fromstring("*:443"), Addr.fromstring("1.2.3.4:443")},
            False, False)
        self.assertTrue(complex_vh.conflicts([self.addr1]))
        self.assertTrue(complex_vh.conflicts([self.addr2]))
        self.assertFalse(complex_vh.conflicts([self.addr_default]))

        self.assertTrue(self.vhost1.conflicts([self.addr2]))
        self.assertFalse(self.vhost1.conflicts([self.addr_default]))

        self.assertFalse(self.vhost2.conflicts([self.addr1,
                                                self.addr_default]))

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

        self.assertTrue(self.vhost1.same_server(self.vhost2))
        self.assertTrue(no_name1.same_server(no_name2))

        self.assertFalse(self.vhost1.same_server(no_name1))
        self.assertFalse(no_name1.same_server(no_name3))
        self.assertFalse(no_name1.same_server(no_name4))


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
        self.assertFalse(self.addr.is_wildcard())
        self.assertTrue(self.addr1.is_wildcard())
        self.assertTrue(self.addr2.is_wildcard())

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
        self.assertTrue(self.addr.conflicts(self.addr1))
        self.assertTrue(self.addr.conflicts(self.addr2))
        self.assertTrue(self.addr.conflicts(self.addr_defined))
        self.assertFalse(self.addr.conflicts(self.addr_default))

        self.assertFalse(self.addr1.conflicts(self.addr))
        self.assertTrue(self.addr1.conflicts(self.addr_defined))
        self.assertFalse(self.addr1.conflicts(self.addr_default))

        self.assertFalse(self.addr_defined.conflicts(self.addr1))
        self.assertFalse(self.addr_defined.conflicts(self.addr2))
        self.assertFalse(self.addr_defined.conflicts(self.addr))
        self.assertFalse(self.addr_defined.conflicts(self.addr_default))

        self.assertTrue(self.addr_default.conflicts(self.addr))
        self.assertTrue(self.addr_default.conflicts(self.addr1))
        self.assertTrue(self.addr_default.conflicts(self.addr_defined))

        # Self test
        self.assertTrue(self.addr.conflicts(self.addr))
        self.assertTrue(self.addr1.conflicts(self.addr1))
        # This is a tricky one...
        self.assertTrue(self.addr1.conflicts(self.addr2))

    def test_equal(self):
        self.assertTrue(self.addr1 == self.addr2)
        self.assertFalse(self.addr == self.addr1)
        self.assertFalse(self.addr == 123)

    def test_not_equal(self):
        self.assertFalse(self.addr1 != self.addr2)
        self.assertTrue(self.addr != self.addr1)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
