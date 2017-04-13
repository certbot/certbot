"""Tests for certbot.plugins.dns_cloudxns."""

import mock
import unittest

from certbot import errors
from requests.exceptions import HTTPError, RequestException

from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN

DOMAIN_NOT_FOUND = Exception('No domain found')
GENERIC_ERROR = RequestException
LOGIN_ERROR = HTTPError('400 Client Error: ...')

API_KEY = 'foo'
SECRET_KEY = 'bar'


class AuthenticatorTest(unittest.TestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot.plugins.dns_cloudxns import Authenticator
        self.config = mock.MagicMock(cloudxns_api_key=API_KEY,
                                     cloudxns_secret_key=SECRET_KEY,
                                     cloudxns_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "cloudxns")

        self.mock_client = mock.MagicMock()
        # _get_cloudxns_client | pylint: disable=protected-access
        self.auth._get_cloudxns_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        # pylint: disable=duplicate-code
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # pylint: disable=duplicate-code
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class CloudXNSLexiconClientTest(unittest.TestCase):
    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"

    def setUp(self):
        from certbot.plugins.dns_cloudxns import _CloudXNSLexiconClient

        self.client = _CloudXNSLexiconClient(API_KEY, SECRET_KEY, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock

    def test_add_txt_record(self):
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content)

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_try_twice_to_find_domain(self):
        self.provider_mock.authenticate.side_effect = [DOMAIN_NOT_FOUND, '']

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content)

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_fail_to_find_domain(self):
        self.provider_mock.authenticate.side_effect = [DOMAIN_NOT_FOUND,
                                                       DOMAIN_NOT_FOUND,
                                                       DOMAIN_NOT_FOUND,]

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_fail_to_authenticate(self):
        self.provider_mock.authenticate.side_effect = LOGIN_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_error_finding_domain(self):
        self.provider_mock.authenticate.side_effect = GENERIC_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_error_adding_record(self):
        self.provider_mock.create_record.side_effect = GENERIC_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record(self):
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.provider_mock.delete_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_del_txt_record_fail_to_find_domain(self):
        self.provider_mock.authenticate.side_effect = [DOMAIN_NOT_FOUND,
                                                       DOMAIN_NOT_FOUND,
                                                       DOMAIN_NOT_FOUND, ]

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_fail_to_authenticate(self):
        self.provider_mock.authenticate.side_effect = LOGIN_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_finding_domain(self):
        self.provider_mock.authenticate.side_effect = GENERIC_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_deleting_record(self):
        self.provider_mock.delete_record.side_effect = GENERIC_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.del_txt_record,
                          DOMAIN, self.record_name, self.record_content)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
