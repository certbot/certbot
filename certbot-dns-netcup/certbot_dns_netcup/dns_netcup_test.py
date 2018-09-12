"""Tests for certbot_dns_netcup.dns_netcup."""

import os
import unittest

import mock

from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from nc_dnsapi import DNSRecord

CUSTOMER_ID  = 123456
API_KEY      = 'an-api-key'
API_PASSWORD = 'an-api-password'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_netcup.dns_netcup import Authenticator

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({
            "netcup_customer_id":   CUSTOMER_ID,
            "netcup_api_key":       API_KEY,
            "netcup_api_password":  API_PASSWORD,
        }, path)

        self.config = mock.MagicMock(netcup_credentials=path,
                                     netcup_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "netcup")

        self.mock_client = mock.MagicMock()
        self.mock_client.__enter__.return_value.dns_record = (
            lambda domain, record: record)
        # _get_netcup_client | pylint: disable=protected-access
        self.auth._get_netcup_client = mock.MagicMock(
            return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_dns_record(DOMAIN, DNSRecord(
            '_acme-challenge', 'TXT', mock.ANY))]

        mock_client = self.mock_client.__enter__.return_value
        self.assertEqual(expected, mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.delete_dns_record(DOMAIN, DNSRecord(
            '_acme-challenge', 'TXT', mock.ANY))]

        mock_client = self.mock_client.__enter__.return_value
        self.assertEqual(expected, mock_client.mock_calls)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
