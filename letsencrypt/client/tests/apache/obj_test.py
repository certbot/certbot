"""Test the helper objects in apache.obj.py."""
import unittest


class AddrTest(unittest.TestCase):
    """Test the Addr class."""
    def setUp(self):
        from letsencrypt.client.apache.obj import Addr
        self.addr1 = Addr.fromstring("192.168.1.1")
        self.addr2 = Addr.fromstring("192.168.1.1:*")
        self.addr3 = Addr.fromstring("192.168.1.1:80")

    def test_fromstring(self):
        self.assertEqual(self.addr1.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr1.get_port(), "")
        self.assertEqual(self.addr2.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr2.get_port(), "*")
        self.assertEqual(self.addr3.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr3.get_port(), "80")

    def test_str(self):
        self.assertEqual(str(self.addr1), "192.168.1.1")
        self.assertEqual(str(self.addr2), "192.168.1.1:*")
        self.assertEqual(str(self.addr3), "192.168.1.1:80")

    def test_get_addr_obj(self):
        self.assertEqual(str(self.addr1.get_addr_obj("443")), "192.168.1.1:443")
        self.assertEqual(str(self.addr2.get_addr_obj("")), "192.168.1.1")
        self.assertEqual(str(self.addr1.get_addr_obj("*")), "192.168.1.1:*")

    def test_eq(self):
        self.assertEqual(self.addr1, self.addr2.get_addr_obj(""))
        self.assertNotEqual(self.addr1, self.addr2)
        # This is specifically designed to hit line 28 but coverage denies me
        # the satisfaction :(
        self.assertNotEqual(self.addr1, 3333)

    def test_set_inclusion(self):
        from letsencrypt.client.apache.obj import Addr
        set_a = set([self.addr1, self.addr2])
        addr1b = Addr.fromstring("192.168.1.1")
        addr2b = Addr.fromstring("192.168.1.1:*")
        set_b = set([addr1b, addr2b])

        self.assertEqual(set_a, set_b)


class VirtualHostTest(unittest.TestCase):
    """Test the VirtualHost class."""
    def setUp(self):
        from letsencrypt.client.apache.obj import VirtualHost
        from letsencrypt.client.apache.obj import Addr
        self.vhost1 = VirtualHost(
            "filep", "vh_path",
            set([Addr.fromstring("localhost")]), False, False)

    def test_eq(self):
        from letsencrypt.client.apache.obj import Addr
        from letsencrypt.client.apache.obj import VirtualHost
        vhost1b = VirtualHost(
            "filep", "vh_path",
            set([Addr.fromstring("localhost")]), False, False)

        self.assertEqual(vhost1b, self.vhost1)
        self.assertEqual(str(vhost1b), str(self.vhost1))
        self.assertNotEqual(vhost1b, 1234)


if __name__ == "__main__":
    unittest.main()
