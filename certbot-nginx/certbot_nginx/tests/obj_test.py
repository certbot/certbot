"""Test the helper objects in certbot_nginx.obj."""
import unittest


class AddrTest(unittest.TestCase):
    """Test the Addr class."""
    def setUp(self):
        from certbot_nginx.obj import Addr
        self.addr1 = Addr.fromstring("192.168.1.1")
        self.addr2 = Addr.fromstring("192.168.1.1:* ssl")
        self.addr3 = Addr.fromstring("192.168.1.1:80")
        self.addr4 = Addr.fromstring("*:80 default_server ssl")
        self.addr5 = Addr.fromstring("myhost")
        self.addr6 = Addr.fromstring("80 default_server spdy")
        self.addr7 = Addr.fromstring("unix:/var/run/nginx.sock")

    def test_fromstring(self):
        self.assertEqual(self.addr1.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr1.get_port(), "")
        self.assertFalse(self.addr1.ssl)
        self.assertFalse(self.addr1.default)

        self.assertEqual(self.addr2.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr2.get_port(), "*")
        self.assertTrue(self.addr2.ssl)
        self.assertFalse(self.addr2.default)

        self.assertEqual(self.addr3.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr3.get_port(), "80")
        self.assertFalse(self.addr3.ssl)
        self.assertFalse(self.addr3.default)

        self.assertEqual(self.addr4.get_addr(), "*")
        self.assertEqual(self.addr4.get_port(), "80")
        self.assertTrue(self.addr4.ssl)
        self.assertTrue(self.addr4.default)

        self.assertEqual(self.addr5.get_addr(), "myhost")
        self.assertEqual(self.addr5.get_port(), "")
        self.assertFalse(self.addr5.ssl)
        self.assertFalse(self.addr5.default)

        self.assertEqual(self.addr6.get_addr(), "")
        self.assertEqual(self.addr6.get_port(), "80")
        self.assertFalse(self.addr6.ssl)
        self.assertTrue(self.addr6.default)

        self.assertEqual(None, self.addr7)

    def test_str(self):
        self.assertEqual(str(self.addr1), "192.168.1.1")
        self.assertEqual(str(self.addr2), "192.168.1.1:* ssl")
        self.assertEqual(str(self.addr3), "192.168.1.1:80")
        self.assertEqual(str(self.addr4), "*:80 default_server ssl")
        self.assertEqual(str(self.addr5), "myhost")
        self.assertEqual(str(self.addr6), "80 default_server")

    def test_eq(self):
        from certbot_nginx.obj import Addr
        new_addr1 = Addr.fromstring("192.168.1.1 spdy")
        self.assertEqual(self.addr1, new_addr1)
        self.assertNotEqual(self.addr1, self.addr2)
        self.assertFalse(self.addr1 == 3333)

    def test_set_inclusion(self):
        from certbot_nginx.obj import Addr
        set_a = set([self.addr1, self.addr2])
        addr1b = Addr.fromstring("192.168.1.1")
        addr2b = Addr.fromstring("192.168.1.1:* ssl")
        set_b = set([addr1b, addr2b])

        self.assertEqual(set_a, set_b)


class VirtualHostTest(unittest.TestCase):
    """Test the VirtualHost class."""
    def setUp(self):
        from certbot_nginx.obj import VirtualHost
        from certbot_nginx.obj import Addr
        self.vhost1 = VirtualHost(
            "filep",
            set([Addr.fromstring("localhost")]), False, False,
            set(['localhost']), [], [])

    def test_eq(self):
        from certbot_nginx.obj import Addr
        from certbot_nginx.obj import VirtualHost
        vhost1b = VirtualHost(
            "filep",
            set([Addr.fromstring("localhost blah")]), False, False,
            set(['localhost']), [], [])

        self.assertEqual(vhost1b, self.vhost1)
        self.assertEqual(str(vhost1b), str(self.vhost1))
        self.assertFalse(vhost1b == 1234)

    def test_str(self):
        stringified = '\n'.join(['file: filep', 'addrs: localhost',
                                 "names: set(['localhost'])", 'ssl: False',
                                 'enabled: False'])
        self.assertEqual(stringified, str(self.vhost1))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
