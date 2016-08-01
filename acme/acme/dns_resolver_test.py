"""Tests for acme.dns_resolver."""
import unittest
import mock

from acme import dns_resolver

try:
    import dns
except ImportError:  # pragma: no cover
    dns = None


def create_txt_response(name, txt_records):
    """
    Returns an RRSet containing the 'txt_records' as the result of a DNS
    query for 'name'.

    This takes advantage of the fact that an Answer object mostly behaves
    like an RRset.
    """
    return dns.rrset.from_text_list(name, 60, "IN", "TXT", txt_records)


class TxtRecordsForNameTest(unittest.TestCase):

    @mock.patch("acme.dns_resolver.dns.resolver.query")
    def test_txt_records_for_name_with_single_response(self, mock_dns):
        mock_dns.return_value = create_txt_response('name', ['response'])
        self.assertEqual(['response'],
                         dns_resolver.txt_records_for_name('name'))

    @mock.patch("acme.dns_resolver.dns.resolver.query")
    def test_txt_records_for_name_with_multiple_responses(self, mock_dns):
        mock_dns.return_value = create_txt_response(
            'name', ['response1', 'response2'])
        self.assertEqual(['response1', 'response2'],
                         dns_resolver.txt_records_for_name('name'))

    @mock.patch("acme.dns_resolver.dns.resolver.query")
    def test_txt_records_for_name_domain_not_found(self, mock_dns):
        mock_dns.side_effect = dns.resolver.NXDOMAIN
        self.assertEquals([], dns_resolver.txt_records_for_name('name'))

    @mock.patch("acme.dns_resolver.dns.resolver.query")
    def test_txt_records_for_name_domain_other_error(self, mock_dns):
        mock_dns.side_effect = dns.exception.DNSException
        self.assertEquals([], dns_resolver.txt_records_for_name('name'))

    def run(self, result=None):
        if dns is None:  # pragma: no cover
            print(self, "... SKIPPING, no dnspython available")
            return
        super(TxtRecordsForNameTest, self).run(result)
