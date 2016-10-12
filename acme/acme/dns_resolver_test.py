"""Tests for acme.dns_resolver."""
import unittest

import mock
from six.moves import reload_module  # pylint: disable=import-error

from acme import errors
from acme import test_util
from acme.dns_resolver import DNS_REQUIREMENT


if test_util.requirement_available(DNS_REQUIREMENT):
    import dns


def create_txt_response(name, txt_records):
    """
    Returns an RRSet containing the 'txt_records' as the result of a DNS
    query for 'name'.

    This takes advantage of the fact that an Answer object mostly behaves
    like an RRset.
    """
    return dns.rrset.from_text_list(name, 60, "IN", "TXT", txt_records)


class TxtRecordsForNameTest(unittest.TestCase):
    """Tests for acme.dns_resolver.txt_records_for_name."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from acme.dns_resolver import txt_records_for_name
        return txt_records_for_name(*args, **kwargs)


@test_util.skip_unless(test_util.requirement_available(DNS_REQUIREMENT),
                       "optional dependency dnspython is not available")
class TxtRecordsForNameWithDnsTest(TxtRecordsForNameTest):
    """Tests for acme.dns_resolver.txt_records_for_name with dns."""
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


class TxtRecordsForNameWithoutDnsTest(TxtRecordsForNameTest):
    """Tests for acme.dns_resolver.txt_records_for_name without dns."""
    def setUp(self):
        from acme import dns_resolver
        dns_resolver.DNS_AVAILABLE = False

    def tearDown(self):
        from acme import dns_resolver
        reload_module(dns_resolver)

    def test_exception_raised(self):
        self.assertRaises(
            errors.DependencyError, self._call, "example.org")


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
