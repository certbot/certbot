"""Base test class for DNS authenticators built on Lexicon."""
import warnings

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

        # Old plugins (or plugins that wish to be compatible with old certbot
        # versions) pass the extra "domain" parameter, accept the call either
        # with or without it.
        expected = [mock.call.add_txt_record('_acme-challenge.'+DOMAIN, mock.ANY)]
        expected_old = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertIn(self.mock_client.mock_calls, [expected, expected_old])

    def test_cleanup(self):
        self.auth._attempt_cleanup = True  # _attempt_cleanup | pylint: disable=protected-access
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record('_acme-challenge.'+DOMAIN, mock.ANY)]
        expected_old = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertIn(self.mock_client.mock_calls, [expected, expected_old])


class BaseLexiconClientTest(object):
    DOMAIN_NOT_FOUND = Exception('No domain found')
    GENERIC_ERROR = RequestException
    LOGIN_ERROR = HTTPError('400 Client Error: ...')
    UNKNOWN_LOGIN_ERROR = HTTPError('500 Surprise! Error: ...')

    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"

    def test_add_txt_record(self):
        self.client.add_txt_record(self.record_name, self.record_content)

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_with_domain_in_kwargs(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.add_txt_record(domain=DOMAIN,
                                       record_name=self.record_name,
                                       record_content=self.record_content)
            assert w is not None
            self.assertEqual(len(w), 1)
            self.assertIn('Domain is now auto-determined', str(w[-1].message))

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_with_domain_in_args(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content)

            assert w is not None
            self.assertEqual(len(w), 1)
            self.assertIn('Domain is now auto-determined', str(w[-1].message))

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_with_mixed_args_1(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.add_txt_record(DOMAIN,
                                       record_name=self.record_name,
                                       record_content=self.record_content)

            assert w is not None
            self.assertEqual(len(w), 1)
            self.assertIn('Domain is now auto-determined', str(w[-1].message))

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_with_mixed_args_2(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.add_txt_record(DOMAIN, self.record_name,
                                       record_content=self.record_content)

            assert w is not None
            self.assertEqual(len(w), 1)
            self.assertIn('Domain is now auto-determined', str(w[-1].message))

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_try_twice_to_find_domain(self):
        self.provider_mock.authenticate.side_effect = [self.DOMAIN_NOT_FOUND, '']

        self.client.add_txt_record(self.record_name, self.record_content)

        self.provider_mock.create_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_fail_to_find_domain(self):
        self.provider_mock.authenticate.side_effect = [self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND,]

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          self.record_name, self.record_content)

    def test_add_txt_record_fail_to_authenticate(self):
        self.provider_mock.authenticate.side_effect = self.LOGIN_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          self.record_name, self.record_content)

    def test_add_txt_record_fail_to_authenticate_with_unknown_error(self):
        self.provider_mock.authenticate.side_effect = self.UNKNOWN_LOGIN_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          self.record_name, self.record_content)

    def test_add_txt_record_error_finding_domain(self):
        self.provider_mock.authenticate.side_effect = self.GENERIC_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          self.record_name, self.record_content)

    def test_add_txt_record_error_adding_record(self):
        self.provider_mock.create_record.side_effect = self.GENERIC_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          self.record_name, self.record_content)

    def test_del_txt_record(self):
        self.client.del_txt_record(self.record_name, self.record_content)

        self.provider_mock.delete_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_del_txt_record_with_domain_in_kwargs(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.del_txt_record(domain=DOMAIN,
                                       record_name=self.record_name,
                                       record_content=self.record_content)
            assert w is not None
            self.assertEqual(len(w), 1)
            self.assertIn('Domain is now auto-determined', str(w[-1].message))

        self.provider_mock.delete_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_del_txt_record_with_domain_in_args(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

            assert w is not None
            self.assertEqual(len(w), 1)
            self.assertIn('Domain is now auto-determined', str(w[-1].message))

        self.provider_mock.delete_record.assert_called_with(type='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_del_txt_record_fail_to_find_domain(self):
        self.provider_mock.authenticate.side_effect = [self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND, ]

        self.client.del_txt_record(self.record_name, self.record_content)

    def test_del_txt_record_fail_to_authenticate(self):
        self.provider_mock.authenticate.side_effect = self.LOGIN_ERROR

        self.client.del_txt_record(self.record_name, self.record_content)

    def test_del_txt_record_fail_to_authenticate_with_unknown_error(self):
        self.provider_mock.authenticate.side_effect = self.UNKNOWN_LOGIN_ERROR

        self.client.del_txt_record(self.record_name, self.record_content)

    def test_del_txt_record_error_finding_domain(self):
        self.provider_mock.authenticate.side_effect = self.GENERIC_ERROR

        self.client.del_txt_record(self.record_name, self.record_content)

    def test_del_txt_record_error_deleting_record(self):
        self.provider_mock.delete_record.side_effect = self.GENERIC_ERROR

        self.client.del_txt_record(self.record_name, self.record_content)
