"""Tests for letsencrypt_apache.obj."""
import unittest

from letsencrypt.plugins import common


class VirtualHostTest(unittest.TestCase):
    """Test the VirtualHost class."""

    def setUp(self):
        from letsencrypt_apache.obj import VirtualHost
        self.vhost1 = VirtualHost(
            "filep", "vh_path",
            set([common.Addr.fromstring("localhost")]), False, False)

    def test_eq(self):
        from letsencrypt_apache.obj import VirtualHost
        vhost1b = VirtualHost(
            "filep", "vh_path",
            set([common.Addr.fromstring("localhost")]), False, False)

        self.assertEqual(vhost1b, self.vhost1)
        self.assertEqual(str(vhost1b), str(self.vhost1))
        self.assertFalse(vhost1b == 1234)


class AddrTest(unittest.TestCase):
    """Test obj.Addr."""
    def setUp(self):
        from letsencrypt_apache.obj import Addr
        self.addr = Addr.fromstring("*:443")

        self.addr1 = Addr.fromstring("127.0.0.1")
        self.addr2 = Addr.fromstring("127.0.0.1:*")

    def test_wildcard(self):
        self.assertFalse(self.addr.is_wildcard())
        self.assertTrue(self.addr1.is_wildcard())
        self.assertTrue(self.addr2.is_wildcard())

    def test_get_sni_addr(self):
        from letsencrypt_apache.obj import Addr
        self.assertEqual(
            self.addr.get_sni_addr("443"), Addr.fromstring("*:443"))
        self.assertEqual(
            self.addr.get_sni_addr("225"), Addr.fromstring("*:225"))
        self.assertEqual(
            self.addr1.get_sni_addr("443"), Addr.fromstring("127.0.0.1"))

    def test_equal(self):
        self.assertTrue(self.addr1 == self.addr2)
        self.assertFalse(self.addr == self.addr1)

    def test_not_equal(self):
        self.assertFalse(self.addr1 != self.addr2)
        self.assertTrue(self.addr != self.addr1)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
