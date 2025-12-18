"""Test the helper objects in certbot._internal.nginx.obj."""
import itertools
import sys
import unittest

import pytest


class AddrTest(unittest.TestCase):
    """Test the Addr class."""
    def setUp(self):
        from certbot._internal.nginx.obj import Addr
        self.addr1 = Addr.fromstring("192.168.1.1")
        self.addr2 = Addr.fromstring("192.168.1.1:* ssl")
        self.addr3 = Addr.fromstring("192.168.1.1:80")
        self.addr4 = Addr.fromstring("*:80 default_server ssl")
        self.addr5 = Addr.fromstring("myhost")
        self.addr6 = Addr.fromstring("80 default_server spdy")
        self.addr7 = Addr.fromstring("*:80 default ssl")

    def test_fromstring(self):
        assert self.addr1.get_addr() == "192.168.1.1"
        assert self.addr1.get_port() == ""
        assert self.addr1.ssl is False
        assert self.addr1.default is False

        assert self.addr2.get_addr() == "192.168.1.1"
        assert self.addr2.get_port() == "*"
        assert self.addr2.ssl is True
        assert self.addr2.default is False

        assert self.addr3.get_addr() == "192.168.1.1"
        assert self.addr3.get_port() == "80"
        assert self.addr3.ssl is False
        assert self.addr3.default is False

        assert self.addr4.get_addr() == "*"
        assert self.addr4.get_port() == "80"
        assert self.addr4.ssl is True
        assert self.addr4.default is True

        assert self.addr5.get_addr() == "myhost"
        assert self.addr5.get_port() == ""
        assert self.addr5.ssl is False
        assert self.addr5.default is False

        assert self.addr6.get_addr() == ""
        assert self.addr6.get_port() == "80"
        assert self.addr6.ssl is False
        assert self.addr6.default is True

        assert self.addr7.default is True

    def test_fromstring_socket(self):
        from certbot._internal.nginx.obj import Addr, SocketAddrError
        socket_string = r"unix:/var/run/nginx.sock"
        with pytest.raises(SocketAddrError, match=socket_string):
            Addr.fromstring(socket_string)

    def test_str(self):
        assert str(self.addr1) == "192.168.1.1"
        assert str(self.addr2) == "192.168.1.1:* ssl"
        assert str(self.addr3) == "192.168.1.1:80"
        assert str(self.addr4) == "*:80 default_server ssl"
        assert str(self.addr5) == "myhost"
        assert str(self.addr6) == "80 default_server"
        assert str(self.addr7) == "*:80 default_server ssl"

    def test_to_string(self):
        assert self.addr1.to_string() == "192.168.1.1"
        assert self.addr2.to_string() == "192.168.1.1:* ssl"
        assert self.addr3.to_string() == "192.168.1.1:80"
        assert self.addr4.to_string() == "*:80 default_server ssl"
        assert self.addr4.to_string(include_default=False) == "*:80 ssl"
        assert self.addr5.to_string() == "myhost"
        assert self.addr6.to_string() == "80 default_server"
        assert self.addr6.to_string(include_default=False) == "80"

    def test_eq(self):
        from certbot._internal.nginx.obj import Addr
        new_addr1 = Addr.fromstring("192.168.1.1 spdy")
        assert self.addr1 == new_addr1
        assert self.addr1 != self.addr2
        assert self.addr1 != 3333

    def test_equivalent_any_addresses(self):
        from certbot._internal.nginx.obj import Addr
        any_addresses = ("0.0.0.0:80 default_server ssl",
                         "80 default_server ssl",
                         "*:80 default_server ssl",
                         "80 default ssl")
        for first, second in itertools.combinations(any_addresses, 2):
            assert Addr.fromstring(first) == Addr.fromstring(second)

        # Also, make sure ports are checked.
        assert Addr.fromstring(any_addresses[0]) != \
                            Addr.fromstring("0.0.0.0:443 default_server ssl")

        # And they aren't equivalent to a specified address.
        for any_address in any_addresses:
            assert Addr.fromstring("192.168.1.2:80 default_server ssl") != \
                Addr.fromstring(any_address)

    def test_set_inclusion(self):
        from certbot._internal.nginx.obj import Addr
        set_a = {self.addr1, self.addr2}
        addr1b = Addr.fromstring("192.168.1.1")
        addr2b = Addr.fromstring("192.168.1.1:* ssl")
        set_b = {addr1b, addr2b}

        assert set_a == set_b


class VirtualHostTest(unittest.TestCase):
    """Test the VirtualHost class."""
    def setUp(self):
        from certbot._internal.nginx.obj import Addr
        from certbot._internal.nginx.obj import VirtualHost
        raw1 = [
            ['listen', '69.50.225.155:9000'],
            [['if', '($scheme', '!=', '"https") '],
                [['return', '301', 'https://$host$request_uri']]
            ],
            ['#', ' managed by Certbot']
        ]
        self.vhost1 = VirtualHost(
            "filep",
            {Addr.fromstring("localhost")}, False, False,
            {'localhost'}, raw1, [])
        raw2 = [
            ['listen', '69.50.225.155:9000'],
            [['if', '($scheme', '!=', '"https") '],
                [['return', '301', 'https://$host$request_uri']]
            ]
        ]
        self.vhost2 = VirtualHost(
            "filep",
            {Addr.fromstring("localhost")}, False, False,
            {'localhost'}, raw2, [])
        raw3 = [
            ['listen', '69.50.225.155:9000'],
            ['rewrite', '^(.*)$', '$scheme://www.domain.com$1', 'permanent']
        ]
        self.vhost3 = VirtualHost(
            "filep",
            {Addr.fromstring("localhost")}, False, False,
            {'localhost'}, raw3, [])
        raw4 = [
            ['listen', '69.50.225.155:9000'],
            ['server_name', 'return.com']
        ]
        self.vhost4 = VirtualHost(
            "filp",
            {Addr.fromstring("localhost")}, False, False,
            {'localhost'}, raw4, [])
        raw_has_hsts = [
            ['listen', '69.50.225.155:9000'],
            ['server_name', 'return.com'],
            ['add_header', 'always', 'set', 'Strict-Transport-Security', '\"max-age=31536000\"'],
        ]
        self.vhost_has_hsts = VirtualHost(
            "filep",
            {Addr.fromstring("localhost")}, False, False,
            {'localhost'}, raw_has_hsts, [])

    def test_eq(self):
        from certbot._internal.nginx.obj import Addr
        from certbot._internal.nginx.obj import VirtualHost
        vhost1b = VirtualHost(
            "filep",
            {Addr.fromstring("localhost blah")}, False, False,
            {'localhost'}, [], [])

        assert vhost1b == self.vhost1
        assert str(vhost1b) == str(self.vhost1)
        assert vhost1b != 1234

    def test_str(self):
        stringified = '\n'.join(['file: filep', 'addrs: localhost',
                                 "names: ['localhost']", 'ssl: False',
                                 'enabled: False'])
        assert stringified == str(self.vhost1)

    def test_has_header(self):
        assert self.vhost_has_hsts.has_header('Strict-Transport-Security') is True
        assert self.vhost_has_hsts.has_header('Bogus-Header') is False
        assert self.vhost1.has_header('Strict-Transport-Security') is False
        assert self.vhost1.has_header('Bogus-Header') is False

    def test_contains_list(self):
        from certbot._internal.nginx.configurator import _test_block_from_block
        from certbot._internal.nginx.obj import Addr
        from certbot._internal.nginx.obj import VirtualHost
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
            {Addr.fromstring("localhost")}, False, False,
            {'localhost'}, test_haystack, [])
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
            {Addr.fromstring("localhost")}, False, False,
            {'localhost'}, test_bad_haystack, [])
        assert vhost_haystack.contains_list(test_needle)
        assert not vhost_bad_haystack.contains_list(test_needle)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
