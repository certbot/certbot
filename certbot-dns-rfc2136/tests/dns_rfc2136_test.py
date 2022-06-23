"""Tests for certbot_dns_rfc2136._internal.dns_rfc2136."""

import unittest
from unittest import mock # type: ignore

import dns.flags
import dns.rcode
import dns.tsig

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

SERVER = '192.0.2.1'
PORT = 53
NAME = 'a-tsig-key.'
SECRET = 'SSB3b25kZXIgd2hvIHdpbGwgYm90aGVyIHRvIGRlY29kZSB0aGlzIHRleHQK'
VALID_CONFIG = {"rfc2136_server": SERVER, "rfc2136_name": NAME, "rfc2136_secret": SECRET}
TIMEOUT = 45


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_rfc2136._internal.dns_rfc2136 import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(VALID_CONFIG, path)

        self.config = mock.MagicMock(rfc2136_credentials=path,
                                     rfc2136_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "rfc2136")

        self.mock_client = mock.MagicMock()
        # _get_rfc2136_client | pylint: disable=protected-access
        self.auth._get_rfc2136_client = mock.MagicMock(return_value=self.mock_client)

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record('_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record('_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_invalid_algorithm_raises(self):
        config = VALID_CONFIG.copy()
        config["rfc2136_algorithm"] = "INVALID"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    @test_util.patch_display_util()
    def test_valid_algorithm_passes(self, unused_mock_get_utility):
        config = VALID_CONFIG.copy()
        config["rfc2136_algorithm"] = "HMAC-sha512"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.auth.perform([self.achall])

    def test_invalid_server_raises(self):
        config = VALID_CONFIG.copy()
        config["rfc2136_server"] = "example.com"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    @test_util.patch_display_util()
    def test_valid_server_passes(self, unused_mock_get_utility):
        config = VALID_CONFIG.copy()
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.auth.perform([self.achall])

        config["rfc2136_server"] = "2001:db8:3333:4444:cccc:dddd:eeee:ffff"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.auth.perform([self.achall])


class RFC2136ClientTest(unittest.TestCase):

    def setUp(self):
        from certbot_dns_rfc2136._internal.dns_rfc2136 import _RFC2136Client

        self.rfc2136_client = _RFC2136Client(SERVER, PORT, NAME, SECRET, dns.tsig.HMAC_MD5,
        TIMEOUT)

    @mock.patch("dns.query.tcp")
    def test_add_txt_record(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NOERROR
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        self.rfc2136_client.add_txt_record("bar", "baz", 42)

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        self.assertIn('bar. 42 IN TXT "baz"', str(query_mock.call_args[0][0]))

    @mock.patch("dns.query.tcp")
    def test_add_txt_record_wraps_errors(self, query_mock):
        query_mock.side_effect = Exception
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        self.assertRaises(
            errors.PluginError,
            self.rfc2136_client.add_txt_record,
             "bar", "baz", 42)

    @mock.patch("dns.query.tcp")
    def test_add_txt_record_server_error(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NXDOMAIN
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        self.assertRaises(
            errors.PluginError,
            self.rfc2136_client.add_txt_record,
             "bar", "baz", 42)

    @mock.patch("dns.query.tcp")
    def test_del_txt_record(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NOERROR
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        self.rfc2136_client.del_txt_record("bar", "baz")

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        self.assertIn('bar. 0 NONE TXT "baz"', str(query_mock.call_args[0][0]))

    @mock.patch("dns.query.tcp")
    def test_del_txt_record_wraps_errors(self, query_mock):
        query_mock.side_effect = Exception
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        self.assertRaises(
            errors.PluginError,
            self.rfc2136_client.del_txt_record,
             "bar", "baz")

    @mock.patch("dns.query.tcp")
    def test_del_txt_record_server_error(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NXDOMAIN
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = mock.MagicMock(return_value="example.com")

        self.assertRaises(
            errors.PluginError,
            self.rfc2136_client.del_txt_record,
             "bar", "baz")

    def test_find_domain(self):
        # _query_soa | pylint: disable=protected-access
        self.rfc2136_client._query_soa = mock.MagicMock(side_effect=[False, False, True])

        # _find_domain | pylint: disable=protected-access
        domain = self.rfc2136_client._find_domain('foo.bar.'+DOMAIN)

        self.assertEqual(domain, DOMAIN)

    def test_find_domain_wraps_errors(self):
        # _query_soa | pylint: disable=protected-access
        self.rfc2136_client._query_soa = mock.MagicMock(return_value=False)

        self.assertRaises(
            errors.PluginError,
            # _find_domain | pylint: disable=protected-access
            self.rfc2136_client._find_domain,
            'foo.bar.'+DOMAIN)

    @mock.patch("dns.query.tcp")
    def test_query_soa_found(self, query_mock):
        query_mock.return_value = mock.MagicMock(answer=[mock.MagicMock()], flags=dns.flags.AA)
        query_mock.return_value.rcode.return_value = dns.rcode.NOERROR

        # _query_soa | pylint: disable=protected-access
        result = self.rfc2136_client._query_soa(DOMAIN)

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        self.assertTrue(result)

    @mock.patch("dns.query.tcp")
    def test_query_soa_not_found(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NXDOMAIN

        # _query_soa | pylint: disable=protected-access
        result = self.rfc2136_client._query_soa(DOMAIN)

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        self.assertFalse(result)

    @mock.patch("dns.query.tcp")
    def test_query_soa_wraps_errors(self, query_mock):
        query_mock.side_effect = Exception

        self.assertRaises(
            errors.PluginError,
            # _query_soa | pylint: disable=protected-access
            self.rfc2136_client._query_soa,
            DOMAIN)

    @mock.patch("dns.query.udp")
    @mock.patch("dns.query.tcp")
    def test_query_soa_fallback_to_udp(self, tcp_mock, udp_mock):
        tcp_mock.side_effect = OSError
        udp_mock.return_value = mock.MagicMock(answer=[mock.MagicMock()], flags=dns.flags.AA)
        udp_mock.return_value.rcode.return_value = dns.rcode.NOERROR

        # _query_soa | pylint: disable=protected-access
        result = self.rfc2136_client._query_soa(DOMAIN)

        tcp_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        udp_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
