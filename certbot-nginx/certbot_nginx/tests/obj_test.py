"""Test the helper objects in certbot_nginx.obj."""
import unittest
import itertools


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
        self.addr8 = Addr.fromstring("*:80 default ssl")

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

        self.assertTrue(self.addr8.default)

        self.assertEqual(None, self.addr7)

    def test_str(self):
        self.assertEqual(str(self.addr1), "192.168.1.1")
        self.assertEqual(str(self.addr2), "192.168.1.1:* ssl")
        self.assertEqual(str(self.addr3), "192.168.1.1:80")
        self.assertEqual(str(self.addr4), "*:80 default_server ssl")
        self.assertEqual(str(self.addr5), "myhost")
        self.assertEqual(str(self.addr6), "80 default_server")
        self.assertEqual(str(self.addr8), "*:80 default_server ssl")

    def test_to_string(self):
        self.assertEqual(self.addr1.to_string(), "192.168.1.1")
        self.assertEqual(self.addr2.to_string(), "192.168.1.1:* ssl")
        self.assertEqual(self.addr3.to_string(), "192.168.1.1:80")
        self.assertEqual(self.addr4.to_string(), "*:80 default_server ssl")
        self.assertEqual(self.addr4.to_string(include_default=False), "*:80 ssl")
        self.assertEqual(self.addr5.to_string(), "myhost")
        self.assertEqual(self.addr6.to_string(), "80 default_server")
        self.assertEqual(self.addr6.to_string(include_default=False), "80")

    def test_eq(self):
        from certbot_nginx.obj import Addr
        new_addr1 = Addr.fromstring("192.168.1.1 spdy")
        self.assertEqual(self.addr1, new_addr1)
        self.assertNotEqual(self.addr1, self.addr2)
        self.assertFalse(self.addr1 == 3333)

    def test_equivalent_any_addresses(self):
        from certbot_nginx.obj import Addr
        any_addresses = ("0.0.0.0:80 default_server ssl",
                         "80 default_server ssl",
                         "*:80 default_server ssl",
                         "80 default ssl")
        for first, second in itertools.combinations(any_addresses, 2):
            self.assertEqual(Addr.fromstring(first), Addr.fromstring(second))

        # Also, make sure ports are checked.
        self.assertNotEqual(Addr.fromstring(any_addresses[0]),
                            Addr.fromstring("0.0.0.0:443 default_server ssl"))

        # And they aren't equivalent to a specified address.
        for any_address in any_addresses:
            self.assertNotEqual(
                Addr.fromstring("192.168.1.2:80 default_server ssl"),
                Addr.fromstring(any_address))

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
        raw1 = [
            ['listen', '69.50.225.155:9000'],
            [['if', '($scheme', '!=', '"https") '],
                [['return', '301', 'https://$host$request_uri']]
            ],
            ['#', ' managed by Certbot']
        ]
        self.vhost1 = VirtualHost(
            "filep",
            set([Addr.fromstring("localhost")]), False, False,
            set(['localhost']), raw1, [])
        raw2 = [
            ['listen', '69.50.225.155:9000'],
            [['if', '($scheme', '!=', '"https") '],
                [['return', '301', 'https://$host$request_uri']]
            ]
        ]
        self.vhost2 = VirtualHost(
            "filep",
            set([Addr.fromstring("localhost")]), False, False,
            set(['localhost']), raw2, [])
        raw3 = [
            ['listen', '69.50.225.155:9000'],
            ['rewrite', '^(.*)$', '$scheme://www.domain.com$1', 'permanent']
        ]
        self.vhost3 = VirtualHost(
            "filep",
            set([Addr.fromstring("localhost")]), False, False,
            set(['localhost']), raw3, [])
        raw4 = [
            ['listen', '69.50.225.155:9000'],
            ['server_name', 'return.com']
        ]
        self.vhost4 = VirtualHost(
            "filp",
            set([Addr.fromstring("localhost")]), False, False,
            set(['localhost']), raw4, [])
        raw_has_hsts = [
            ['listen', '69.50.225.155:9000'],
            ['server_name', 'return.com'],
            ['add_header', 'always', 'set', 'Strict-Transport-Security', '\"max-age=31536000\"'],
        ]
        self.vhost_has_hsts = VirtualHost(
            "filep",
            set([Addr.fromstring("localhost")]), False, False,
            set(['localhost']), raw_has_hsts, [])

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
                                 "names: ['localhost']", 'ssl: False',
                                 'enabled: False'])
        self.assertEqual(stringified, str(self.vhost1))

    def test_has_header(self):
        self.assertTrue(self.vhost_has_hsts.has_header('Strict-Transport-Security'))
        self.assertFalse(self.vhost_has_hsts.has_header('Bogus-Header'))
        self.assertFalse(self.vhost1.has_header('Strict-Transport-Security'))
        self.assertFalse(self.vhost1.has_header('Bogus-Header'))

    def test_contains_list(self):
        from certbot_nginx.obj import VirtualHost
        from certbot_nginx.obj import Addr
        from certbot_nginx.configurator import _test_block_from_block
        test_block = [
            ['\n    ', 'return', ' ', '301', ' ', 'https://$host$request_uri'],
            ['\n']
        ]
        test_needle = _test_block_from_block(test_block)
        test_haystack = [['listen', '80'], ['root', '/var/www/html'],
            ['index', 'index.html index.htm index.nginx-debian.html'],
            ['server_name', 'two.functorkitten.xyz'], ['listen', '443 ssl'],
            ['#', ' managed by Certbot'],
            ['ssl_certificate', '/etc/letsencrypt/live/two.functorkitten.xyz/fullchain.pem'],
            ['#', ' managed by Certbot'],
            ['ssl_certificate_key', '/etc/letsencrypt/live/two.functorkitten.xyz/privkey.pem'],
            ['#', ' managed by Certbot'],
            ['return', '301', 'https://$host$request_uri'],
            ['#', ' managed by Certbot'], []]
        vhost_haystack = VirtualHost(
            "filp",
            set([Addr.fromstring("localhost")]), False, False,
            set(['localhost']), test_haystack, [])
        test_bad_haystack = [['listen', '80'], ['root', '/var/www/html'],
            ['index', 'index.html index.htm index.nginx-debian.html'],
            ['server_name', 'two.functorkitten.xyz'], ['listen', '443 ssl'],
            ['#', ' managed by Certbot'],
            ['ssl_certificate', '/etc/letsencrypt/live/two.functorkitten.xyz/fullchain.pem'],
            ['#', ' managed by Certbot'],
            ['ssl_certificate_key', '/etc/letsencrypt/live/two.functorkitten.xyz/privkey.pem'],
            ['#', ' managed by Certbot'],
            [['if', '($scheme', '!=', '"https")'],
             [['return', '302', 'https://$host$request_uri']]
            ],
            ['#', ' managed by Certbot'], []]
        vhost_bad_haystack = VirtualHost(
            "filp",
            set([Addr.fromstring("localhost")]), False, False,
            set(['localhost']), test_bad_haystack, [])
        self.assertTrue(vhost_haystack.contains_list(test_needle))
        self.assertFalse(vhost_bad_haystack.contains_list(test_needle))

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
