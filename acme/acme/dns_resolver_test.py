"""Tests for acme.dns_resolver."""
import sys
import unittest

import mock

from acme import test_util


try:
    import dns
    DNS_AVAILABLE = True  # pragma: no cover
except ImportError:  # pragma: no cover
    DNS_AVAILABLE = False


def create_txt_response(name, txt_records):
    """
    Returns an RRSet containing the 'txt_records' as the result of a DNS
    query for 'name'.

    This takes advantage of the fact that an Answer object mostly behaves
    like an RRset.
    """
    return dns.rrset.from_text_list(name, 60, "IN", "TXT", txt_records)


@test_util.skip_unless(DNS_AVAILABLE,
                       "optional dependency dnspython is not available")
class DnsResolverTestWithDns(unittest.TestCase):
    """Tests for acme.dns_resolver when dns is available."""
    @classmethod
    def _call(cls, name):
        from acme import dns_resolver
        return dns_resolver.txt_records_for_name(name)

    @mock.patch("acme.dns_resolver.dns.resolver.query")
    def test_txt_records_for_name_with_single_response(self, mock_dns):
        mock_dns.return_value = create_txt_response('name', ['response'])
        self.assertEqual(['response'], self._call('name'))

    @mock.patch("acme.dns_resolver.dns.resolver.query")
    def test_txt_records_for_name_with_multiple_responses(self, mock_dns):
        mock_dns.return_value = create_txt_response(
            'name', ['response1', 'response2'])
        self.assertEqual(['response1', 'response2'], self._call('name'))

    @mock.patch("acme.dns_resolver.dns.resolver.query")
    def test_txt_records_for_name_domain_not_found(self, mock_dns):
        mock_dns.side_effect = dns.resolver.NXDOMAIN
        self.assertEquals([], self._call('name'))

    @mock.patch("acme.dns_resolver.dns.resolver.query")
    def test_txt_records_for_name_domain_other_error(self, mock_dns):
        mock_dns.side_effect = dns.exception.DNSException
        self.assertEquals([], self._call('name'))


class DnsResolverTestWithoutDns(unittest.TestCase):
    """Tests for acme.dns_resolver when dns is unavailable."""
    def setUp(self):
        self.dns_module = sys.modules['dns'] if 'dns' in sys.modules else None

        if DNS_AVAILABLE:
            sys.modules['dns'] = None  # pragma: no cover

    def tearDown(self):
        if self.dns_module is not None:
            sys.modules['dns'] = self.dns_module  # pragma: no cover

    @classmethod
    def _import_dns(cls):
        import dns as failed_dns_import  # pylint: disable=unused-variable

    def test_import_error_is_raised(self):
        self.assertRaises(ImportError, self._import_dns)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
