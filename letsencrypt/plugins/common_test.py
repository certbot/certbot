"""Tests for letsencrypt.plugins.common."""
import pkg_resources
import unittest

import mock

from acme import challenges

from letsencrypt import achallenges
from letsencrypt import le_util

from letsencrypt.tests import acme_util


class NamespaceFunctionsTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.common.*_namespace functions."""

    def test_option_namespace(self):
        from letsencrypt.plugins.common import option_namespace
        self.assertEqual("foo-", option_namespace("foo"))

    def test_dest_namespace(self):
        from letsencrypt.plugins.common import dest_namespace
        self.assertEqual("foo_", dest_namespace("foo"))


class PluginTest(unittest.TestCase):
    """Test for letsencrypt.plugins.common.Plugin."""

    def setUp(self):
        from letsencrypt.plugins.common import Plugin

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
    """Tests for letsencrypt.client.plugins.common.Addr."""

    def setUp(self):
        from letsencrypt.plugins.common import Addr
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
        self.assertFalse(self.addr1 == 3333)

    def test_set_inclusion(self):
        from letsencrypt.plugins.common import Addr
        set_a = set([self.addr1, self.addr2])
        addr1b = Addr.fromstring("192.168.1.1")
        addr2b = Addr.fromstring("192.168.1.1:*")
        set_b = set([addr1b, addr2b])

        self.assertEqual(set_a, set_b)


class DvsniTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.common.DvsniTest."""

    rsa256_file = pkg_resources.resource_filename(
        "acme.jose", "testdata/rsa256_key.pem")
    rsa256_pem = pkg_resources.resource_string(
        "acme.jose", "testdata/rsa256_key.pem")

    auth_key = le_util.Key(rsa256_file, rsa256_pem)
    achalls = [
        achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(
                    r="\x8c\x8a\xbf_-f\\cw\xee\xd6\xf8/\xa5\xe3\xfd\xeb9"
                      "\xf1\xf5\xb9\xefVM\xc9w\xa4u\x9c\xe1\x87\xb4",
                    nonce="7\xbc^\xb7]>\x00\xa1\x9bOcU\x84^Z\x18",
                ), "pending"),
            domain="encryption-example.demo", key=auth_key),
        achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(
                    r="\xba\xa9\xda?<m\xaewmx\xea\xad\xadv\xf4\x02\xc9y\x80"
                    "\xe2_X\t\xe7\xc7\xa4\t\xca\xf7&\x945",
                    nonce="Y\xed\x01L\xac\x95\xf7pW\xb1\xd7\xa1\xb2\xc5"
                          "\x96\xba",
                ), "pending"),
            domain="letsencrypt.demo", key=auth_key),
    ]

    def setUp(self):
        from letsencrypt.plugins.common import Dvsni
        self.sni = Dvsni(configurator=mock.MagicMock())

    def test_setup_challenge_cert(self):
        # This is a helper function that can be used for handling
        # open context managers more elegantly. It avoids dealing with
        # __enter__ and __exit__ calls.
        # http://www.voidspace.org.uk/python/mock/helpers.html#mock.mock_open
        m_open = mock.mock_open()

        response = challenges.DVSNIResponse(s="randomS1")
        achall = mock.MagicMock(nonce=self.achalls[0].nonce,
                                nonce_domain=self.achalls[0].nonce_domain)
        achall.gen_cert_and_response.return_value = ("pem", response)

        with mock.patch("letsencrypt.plugins.common.open", m_open, create=True):
            # pylint: disable=protected-access
            self.assertEqual(response, self.sni._setup_challenge_cert(
                achall, "randomS1"))

            self.assertTrue(m_open.called)
            self.assertEqual(
                m_open.call_args[0], (self.sni.get_cert_file(achall), "w"))
            self.assertEqual(m_open().write.call_args[0][0], "pem")


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
