"""Base test class for DNS authenticators built on Lexicon."""

import josepy as jose
import mock
from requests.exceptions import HTTPError
from requests.exceptions import RequestException

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.tests import util as test_util

DOMAIN = 'example.com'
KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))

# These classes are intended to be subclassed/mixed in, so not all members are defined.
# pylint: disable=no-member

class BaseLexiconAuthenticatorTest(dns_test_common.BaseAuthenticatorTest):

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        self.auth._attempt_cleanup = True  # _attempt_cleanup | pylint: disable=protected-access
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class BaseLexiconClientTest(object):
    DOMAIN_NOT_FOUND = Exception('No domain found')
    GENERIC_ERROR = RequestException
    LOGIN_ERROR = HTTPError('400 Client Error: ...')
    UNKNOWN_LOGIN_ERROR = HTTPError('500 Surprise! Error: ...')

    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"

    def test_add_txt_record(self):
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content)

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_try_twice_to_find_domain(self):
        self.provider_mock.authenticate.side_effect = [self.DOMAIN_NOT_FOUND, '']

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content)

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_fail_to_find_domain(self):
        self.provider_mock.authenticate.side_effect = [self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND,]

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_fail_to_authenticate(self):
        self.provider_mock.authenticate.side_effect = self.LOGIN_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_fail_to_authenticate_with_unknown_error(self):
        self.provider_mock.authenticate.side_effect = self.UNKNOWN_LOGIN_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_error_finding_domain(self):
        self.provider_mock.authenticate.side_effect = self.GENERIC_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_error_adding_record(self):
        self.provider_mock.create_record.side_effect = self.GENERIC_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record(self):
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.provider_mock.delete_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_del_txt_record_fail_to_find_domain(self):
        self.provider_mock.authenticate.side_effect = [self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND, ]

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_fail_to_authenticate(self):
        self.provider_mock.authenticate.side_effect = self.LOGIN_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_fail_to_authenticate_with_unknown_error(self):
        self.provider_mock.authenticate.side_effect = self.UNKNOWN_LOGIN_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_finding_domain(self):
        self.provider_mock.authenticate.side_effect = self.GENERIC_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_deleting_record(self):
        self.provider_mock.delete_record.side_effect = self.GENERIC_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)
