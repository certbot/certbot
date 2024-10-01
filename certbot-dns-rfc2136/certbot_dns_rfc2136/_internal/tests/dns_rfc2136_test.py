"""Tests for certbot_dns_rfc2136._internal.dns_rfc2136."""

import sys
import unittest
from unittest import mock

import dns.flags
import dns.message
import dns.name
import dns.namedict
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.DNAME
import dns.rdtypes.ANY.SOA
import dns.tsig
import pytest

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
        self.orig_get_client = self.auth._get_rfc2136_client
        self.auth._get_rfc2136_client = mock.MagicMock(return_value=self.mock_client)

    def test_get_client_default_conf_values(self):
        # algorithm and sign_query are intentionally absent to test that the default (None)
        # value does not crash Certbot.
        creds = { "server": SERVER, "port": PORT, "name": NAME, "secret": SECRET }
        self.auth.credentials = mock.MagicMock()
        self.auth.credentials.conf = lambda key: creds.get(key, None)
        client = self.orig_get_client()
        assert client.algorithm == self.auth.ALGORITHMS["HMAC-MD5"]
        assert client.sign_query == False

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record('_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record('_acme-challenge.'+DOMAIN, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_invalid_algorithm_raises(self):
        config = VALID_CONFIG.copy()
        config["rfc2136_algorithm"] = "INVALID"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

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

        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    @test_util.patch_display_util()
    def test_valid_server_passes(self, unused_mock_get_utility):
        config = VALID_CONFIG.copy()
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.auth.perform([self.achall])

        config["rfc2136_server"] = "2001:db8:3333:4444:cccc:dddd:eeee:ffff"
        dns_test_common.write(config, self.config.rfc2136_credentials)

        self.auth.perform([self.achall])


class RFC2136ClientTest(unittest.TestCase):

    def _stub_query_soa(self, domain):
        rrname, retval = self._query_soa_return.get_deepest_match(domain)
        if domain != rrname:
            return retval[0], None  # Just the authoritative flag
        return retval

    def setUp(self):
        from certbot_dns_rfc2136._internal.dns_rfc2136 import _RFC2136Client

        self.rfc2136_client = _RFC2136Client(SERVER, PORT, NAME, SECRET, dns.tsig.HMAC_MD5,
        False, TIMEOUT)
        self.domain = dns.name.from_text(DOMAIN)
        self.prefix = dict()  # type: Dict[str, dns.name.Name]
        self.subdom = dict()  # type: Dict[str, dns.name.Name]
        for pfx in 'foo', 'bar', 'foo.bar', 'baz', 'quux', 'cname', 'dname', 'subzone', 'bad', \
          'foo.bar.subzone', 'foo.bar.cname', 'my.challenge', 'my.challenge.subzone':
            self.prefix[pfx] = dns.name.from_text(pfx, dns.name.empty)
            self.subdom[pfx] = self.prefix[pfx] + self.domain

        # _find_domain stub -> (bar, DOMAIN.)
        self._mock_find_domain = mock.MagicMock(return_value=(self.prefix['bar'], self.domain))

        # Mock DNS records
        soa_rr = dns.rdtypes.ANY.SOA.SOA(dns.rdataclass.IN, dns.rdatatype.SOA,
                                         SERVER, SERVER, 1, 2, 3, 4, 5)
        cname_rr = dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME,
                                               self.subdom['foo.bar.subzone'])
        cname_challenge_rr = dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME,
                                               self.subdom['my.challenge.subzone'])
        dname_rr = dns.rdtypes.ANY.DNAME.DNAME(dns.rdataclass.IN, dns.rdatatype.DNAME,
                                               self.subdom['subzone'])
        self._query_soa_return = \
            dns.namedict.NameDict({dns.name.root: (False, soa_rr),
                                   self.domain: (True, soa_rr),
                                   self.subdom['subzone']: (True, soa_rr),
                                   self.subdom['cname']: (True, cname_rr),
                                   self.subdom['foo.bar.cname']: (True, cname_challenge_rr),
                                   self.subdom['dname']: (False, dname_rr),
                                   self.subdom['bad']: (False, soa_rr)})
        self._mock_query_soa = mock.MagicMock(side_effect=self._stub_query_soa)

    @mock.patch("dns.query.tcp")
    def test_add_txt_record(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NOERROR
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = self._mock_find_domain

        self.rfc2136_client.add_txt_record("bar"+DOMAIN, "baz", 42)

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        self.assertTrue("bar 42 IN TXT \"baz\"" in str(query_mock.call_args[0][0]))

    @mock.patch("dns.query.tcp")
    def test_add_txt_record_wraps_errors(self, query_mock):
        query_mock.side_effect = Exception
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = self._mock_find_domain

        with pytest.raises(errors.PluginError):
            self.rfc2136_client.add_txt_record("bar", "baz", 42)

    @mock.patch("dns.query.tcp")
    def test_add_txt_record_server_error(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NXDOMAIN
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = self._mock_find_domain

        with pytest.raises(errors.PluginError):
            self.rfc2136_client.add_txt_record("bar", "baz", 42)

    @mock.patch("dns.query.tcp")
    def test_del_txt_record(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NOERROR
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = self._mock_find_domain

        self.rfc2136_client.del_txt_record("bar", "baz")

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        self.assertTrue("bar 0 NONE TXT \"baz\"" in str(query_mock.call_args[0][0]))

    @mock.patch("dns.query.tcp")
    def test_del_txt_record_wraps_errors(self, query_mock):
        query_mock.side_effect = Exception
        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = self._mock_find_domain

        with pytest.raises(errors.PluginError):
            self.rfc2136_client.del_txt_record("bar", "baz")

    @mock.patch("dns.query.tcp")
    def test_del_txt_record_server_error(self, query_mock):
        query_mock.return_value.rcode.return_value = dns.rcode.NXDOMAIN

        # _find_domain | pylint: disable=protected-access
        self.rfc2136_client._find_domain = self._mock_find_domain

        self.assertRaises(
            errors.PluginError,
            self.rfc2136_client.del_txt_record,
            "bar", "baz")

    def test_find_domain(self):
        # _query_soa | pylint: disable=protected-access
        self.rfc2136_client._query_soa = self._mock_query_soa

        # _find_domain | pylint: disable=protected-access
        (prefix, domain) = self.rfc2136_client._find_domain('foo.bar.'+DOMAIN)

        self.assertTrue(domain == self.domain)
        self.assertTrue(prefix == self.prefix['foo.bar'])

    def test_find_domain_cname(self):
        # _query_soa | pylint: disable=protected-access
        self.rfc2136_client._query_soa = self._mock_query_soa

        # _find_domain | pylint: disable=protected-access
        (prefix, domain) = self.rfc2136_client._find_domain('cname.'+DOMAIN)

        self.assertTrue(domain == self.subdom['subzone'])
        self.assertTrue(prefix == self.prefix['foo.bar'])

        assert domain == DOMAIN

    def test_find_domain_wraps_errors(self):
        # _query_soa | pylint: disable=protected-access
        self.rfc2136_client._query_soa = self._mock_query_soa

        self.assertRaises(
            errors.PluginError,
            # _find_domain | pylint: disable=protected-access
            self.rfc2136_client._find_domain, 'error.bad.domain')

    def _stub_dns_noerror(self, dns_query, server, port):  # pylint: disable=unused-argument
        response = dns.message.make_response(dns_query)
        response.rcode = dns.rcode.NOERROR
        response.flags = dns.flags.AA
        return response

    @mock.patch("dns.query.tcp")
    def test_query_soa_found(self, query_mock):
        query_mock.return_value = mock.MagicMock(side_effect=self._stub_dns_noerror)

        # _query_soa | pylint: disable=protected-access
        result = self.rfc2136_client._query_soa(self.domain)

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        self.assertTrue(result == (True, None))

    def _stub_dns_nxdomain(self, dns_query, server, port):  # pylint: disable=unused-argument
        response = dns.message.make_response(dns_query)
        response.rcode = dns.rcode.NXDOMAIN
        response.flags = dns.flags.AA
        return response

    @mock.patch("dns.query.tcp")
    def test_query_soa_not_found(self, query_mock):
        query_mock.return_value = mock.MagicMock(side_effect=self._stub_dns_nxdomain)

        # _query_soa | pylint: disable=protected-access
        result = self.rfc2136_client._query_soa(self.domain)

        query_mock.assert_called_with(mock.ANY, SERVER, TIMEOUT, PORT)
        self.assertTrue(result == (True, None))

    @mock.patch("dns.query.tcp")
    def test_query_soa_wraps_errors(self, query_mock):
        query_mock.side_effect = Exception

        with pytest.raises(errors.PluginError):
            self.rfc2136_client._query_soa(DOMAIN)

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
        assert result

    @mock.patch("dns.query.tcp")
    @mock.patch("dns.message.make_query")
    def test_query_soa_signed(self, mock_make_query, unused_mock_query):
        mock_make_query.return_value = mock.MagicMock()
        self.rfc2136_client.sign_query = True
        self.rfc2136_client.algorithm = "alg0"

        self.rfc2136_client._query_soa(DOMAIN)

        mock_make_query.return_value.use_tsig.assert_called_with(mock.ANY, algorithm="alg0")


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
