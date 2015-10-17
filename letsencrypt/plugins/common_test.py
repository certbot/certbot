"""Tests for letsencrypt.plugins.common."""
import unittest

import mock
import OpenSSL

from acme import challenges
from acme import jose

from letsencrypt import achallenges

from letsencrypt.tests import acme_util
from letsencrypt.tests import test_util


class NamespaceFunctionsTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.common.*_namespace functions."""

    def test_option_namespace(self):
        from letsencrypt.plugins.common import option_namespace
        self.assertEqual("foo-", option_namespace("foo"))

    def test_dest_namespace(self):
        from letsencrypt.plugins.common import dest_namespace
        self.assertEqual("foo_", dest_namespace("foo"))

    def test_dest_namespace_with_dashes(self):
        from letsencrypt.plugins.common import dest_namespace
        self.assertEqual("foo_bar_", dest_namespace("foo-bar"))


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

    auth_key = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))
    achalls = [
        achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(token=b'dvsni1'), "pending"),
            domain="encryption-example.demo", account_key=auth_key),
        achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(token=b'dvsni2'), "pending"),
            domain="letsencrypt.demo", account_key=auth_key),
    ]

    def setUp(self):
        from letsencrypt.plugins.common import Dvsni
        self.sni = Dvsni(configurator=mock.MagicMock())

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

        response = challenges.DVSNIResponse(validation=mock.Mock())
        achall = mock.MagicMock()
        key = test_util.load_pyopenssl_private_key("rsa512_key.pem")
        achall.gen_cert_and_response.return_value = (
            response, test_util.load_cert("cert.pem"), key)

        with mock.patch("letsencrypt.plugins.common.open",
                        mock_open, create=True):
            with mock.patch("letsencrypt.plugins.common.le_util.safe_open",
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
