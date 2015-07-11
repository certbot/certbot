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


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
