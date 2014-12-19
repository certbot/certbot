import unittest

from letsencrypt.client.apache import obj


class AddrTest(unittest.TestCase):
    """Test the Addr class."""
    def setUp(self):
        self.addr1 = obj.Addr.fromstring("192.168.1.1")
        self.addr2 = obj.Addr.fromstring("192.168.1.1:*")
        self.addr3 = obj.Addr.fromstring("192.168.1.1:80")

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
        set_a = set([self.addr1, self.addr2])
        addr1b = obj.Addr.fromstring("192.168.1.1")
        addr2b = obj.Addr.fromstring("192.168.1.1:*")
        set_b = set([addr1b, addr2b])

        self.assertTrue(addr1b in set_a)
        self.assertEqual(set_a, set_b)


class VirtualHostTest(unittest.TestCase):
    """Test the VirtualHost class."""
    def setUp(self):
        self.vhost1 = obj.VirtualHost(
            "filep", "vh_path",
            set([obj.Addr.fromstring("localhost")]), False, False)

    def test_eq(self):
        vhost1b = obj.VirtualHost(
            "filep", "vh_path",
            set([obj.Addr.fromstring("localhost")]), False, False)

        self.assertEqual(vhost1b, self.vhost1)
        self.assertEqual(str(vhost1b), str(self.vhost1))
        self.assertTrue(vhost1b != 1234)
