"""Tests for certbot.plugins.common."""
import os
import shutil
import tempfile
import unittest

import mock
import OpenSSL

from acme import challenges
from acme import jose

from certbot import achallenges

from certbot.tests import acme_util
from certbot.tests import util as test_util


class NamespaceFunctionsTest(unittest.TestCase):
    """Tests for certbot.plugins.common.*_namespace functions."""

    def test_option_namespace(self):
        from certbot.plugins.common import option_namespace
        self.assertEqual("foo-", option_namespace("foo"))

    def test_dest_namespace(self):
        from certbot.plugins.common import dest_namespace
        self.assertEqual("foo_", dest_namespace("foo"))

    def test_dest_namespace_with_dashes(self):
        from certbot.plugins.common import dest_namespace
        self.assertEqual("foo_bar_", dest_namespace("foo-bar"))


class PluginTest(unittest.TestCase):
    """Test for certbot.plugins.common.Plugin."""

    def setUp(self):
        from certbot.plugins.common import Plugin

        class MockPlugin(Plugin):  # pylint: disable=missing-docstring
            @classmethod
            def add_parser_arguments(cls, add):
                add("foo-bar", dest="different_to_foo_bar", x=1, y=None)

        self.plugin_cls = MockPlugin
        self.config = mock.MagicMock()
        self.plugin = MockPlugin(config=self.config, name="mock")

    def test_init(self):
        self.assertEqual("mock", self.plugin.name)
        self.assertEqual(self.config, self.plugin.config)

    def test_option_namespace(self):
        self.assertEqual("mock-", self.plugin.option_namespace)

    def test_option_name(self):
        self.assertEqual("mock-foo_bar", self.plugin.option_name("foo_bar"))

    def test_dest_namespace(self):
        self.assertEqual("mock_", self.plugin.dest_namespace)

    def test_dest(self):
        self.assertEqual("mock_foo_bar", self.plugin.dest("foo-bar"))
        self.assertEqual("mock_foo_bar", self.plugin.dest("foo_bar"))

    def test_conf(self):
        self.assertEqual(self.config.mock_foo_bar, self.plugin.conf("foo-bar"))

    def test_inject_parser_options(self):
        parser = mock.MagicMock()
        self.plugin_cls.inject_parser_options(parser, "mock")
        # note that inject_parser_options doesn't check if dest has
        # correct prefix
        parser.add_argument.assert_called_once_with(
            "--mock-foo-bar", dest="different_to_foo_bar", x=1, y=None)


class AddrTest(unittest.TestCase):
    """Tests for certbot.client.plugins.common.Addr."""

    def setUp(self):
        from certbot.plugins.common import Addr
        self.addr1 = Addr.fromstring("192.168.1.1")
        self.addr2 = Addr.fromstring("192.168.1.1:*")
        self.addr3 = Addr.fromstring("192.168.1.1:80")
        self.addr4 = Addr.fromstring("[fe00::1]")
        self.addr5 = Addr.fromstring("[fe00::1]:*")
        self.addr6 = Addr.fromstring("[fe00::1]:80")
        self.addr7 = Addr.fromstring("[fe00::1]:5")
        self.addr8 = Addr.fromstring("[fe00:1:2:3:4:5:6:7:8:9]:8080")

    def test_fromstring(self):
        self.assertEqual(self.addr1.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr1.get_port(), "")
        self.assertEqual(self.addr2.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr2.get_port(), "*")
        self.assertEqual(self.addr3.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr3.get_port(), "80")
        self.assertEqual(self.addr4.get_addr(), "[fe00::1]")
        self.assertEqual(self.addr4.get_port(), "")
        self.assertEqual(self.addr5.get_addr(), "[fe00::1]")
        self.assertEqual(self.addr5.get_port(), "*")
        self.assertEqual(self.addr6.get_addr(), "[fe00::1]")
        self.assertEqual(self.addr6.get_port(), "80")
        self.assertEqual(self.addr6.get_ipv6_exploded(),
                         "fe00:0:0:0:0:0:0:1")
        self.assertEqual(self.addr1.get_ipv6_exploded(),
                         "")
        self.assertEqual(self.addr7.get_port(), "5")
        self.assertEqual(self.addr8.get_ipv6_exploded(),
                         "fe00:1:2:3:4:5:6:7")

    def test_str(self):
        self.assertEqual(str(self.addr1), "192.168.1.1")
        self.assertEqual(str(self.addr2), "192.168.1.1:*")
        self.assertEqual(str(self.addr3), "192.168.1.1:80")
        self.assertEqual(str(self.addr4), "[fe00::1]")
        self.assertEqual(str(self.addr5), "[fe00::1]:*")
        self.assertEqual(str(self.addr6), "[fe00::1]:80")

    def test_get_addr_obj(self):
        self.assertEqual(str(self.addr1.get_addr_obj("443")), "192.168.1.1:443")
        self.assertEqual(str(self.addr2.get_addr_obj("")), "192.168.1.1")
        self.assertEqual(str(self.addr1.get_addr_obj("*")), "192.168.1.1:*")
        self.assertEqual(str(self.addr4.get_addr_obj("443")), "[fe00::1]:443")
        self.assertEqual(str(self.addr5.get_addr_obj("")), "[fe00::1]")
        self.assertEqual(str(self.addr4.get_addr_obj("*")), "[fe00::1]:*")

    def test_eq(self):
        self.assertEqual(self.addr1, self.addr2.get_addr_obj(""))
        self.assertNotEqual(self.addr1, self.addr2)
        self.assertFalse(self.addr1 == 3333)

        self.assertEqual(self.addr4, self.addr4.get_addr_obj(""))
        self.assertNotEqual(self.addr4, self.addr5)
        self.assertFalse(self.addr4 == 3333)
        from certbot.plugins.common import Addr
        self.assertEqual(self.addr4, Addr.fromstring("[fe00:0:0::1]"))
        self.assertEqual(self.addr4, Addr.fromstring("[fe00:0::0:0:1]"))


    def test_set_inclusion(self):
        from certbot.plugins.common import Addr
        set_a = set([self.addr1, self.addr2])
        addr1b = Addr.fromstring("192.168.1.1")
        addr2b = Addr.fromstring("192.168.1.1:*")
        set_b = set([addr1b, addr2b])

        self.assertEqual(set_a, set_b)

        set_c = set([self.addr4, self.addr5])
        addr4b = Addr.fromstring("[fe00::1]")
        addr5b = Addr.fromstring("[fe00::1]:*")
        set_d = set([addr4b, addr5b])

        self.assertEqual(set_c, set_d)


class TLSSNI01Test(unittest.TestCase):
    """Tests for certbot.plugins.common.TLSSNI01."""

    auth_key = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))
    achalls = [
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.TLSSNI01(token=b'token1'), "pending"),
            domain="encryption-example.demo", account_key=auth_key),
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.TLSSNI01(token=b'token2'), "pending"),
            domain="certbot.demo", account_key=auth_key),
    ]

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        configurator = mock.MagicMock()
        configurator.config.config_dir = os.path.join(self.tempdir, "config")
        configurator.config.work_dir = os.path.join(self.tempdir, "work")

        from certbot.plugins.common import TLSSNI01
        self.sni = TLSSNI01(configurator=configurator)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_add_chall(self):
        self.sni.add_chall(self.achalls[0], 0)
        self.assertEqual(1, len(self.sni.achalls))
        self.assertEqual([0], self.sni.indices)

    def test_setup_challenge_cert(self):
        # This is a helper function that can be used for handling
        # open context managers more elegantly. It avoids dealing with
        # __enter__ and __exit__ calls.
        # http://www.voidspace.org.uk/python/mock/helpers.html#mock.mock_open
        mock_open, mock_safe_open = mock.mock_open(), mock.mock_open()

        response = challenges.TLSSNI01Response()
        achall = mock.MagicMock()
        achall.chall.encode.return_value = "token"
        key = test_util.load_pyopenssl_private_key("rsa512_key.pem")
        achall.response_and_validation.return_value = (
            response, (test_util.load_cert("cert.pem"), key))

        with mock.patch("certbot.plugins.common.open",
                        mock_open, create=True):
            with mock.patch("certbot.plugins.common.util.safe_open",
                            mock_safe_open):
                # pylint: disable=protected-access
                self.assertEqual(response, self.sni._setup_challenge_cert(
                    achall, "randomS1"))

        # pylint: disable=no-member
        mock_open.assert_called_once_with(self.sni.get_cert_path(achall), "wb")
        mock_open.return_value.write.assert_called_once_with(
            test_util.load_vector("cert.pem"))
        mock_safe_open.assert_called_once_with(
            self.sni.get_key_path(achall), "wb", chmod=0o400)
        mock_safe_open.return_value.write.assert_called_once_with(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
