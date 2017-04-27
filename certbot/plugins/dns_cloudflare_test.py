"""Tests for certbot.plugins.dns_cloudflare."""

import mock
import unittest

from certbot import errors

from certbot.display import util as display_util

from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN

from certbot.tests import util as test_util

import CloudFlare

API_ERROR = CloudFlare.exceptions.CloudFlareAPIError(1000, '', '')
API_KEY = 'an-api-key'
EMAIL = 'example@example.com'


class AuthenticatorTest(unittest.TestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot.plugins.dns_cloudflare import Authenticator
        self.config = mock.MagicMock(cloudflare_email=EMAIL,
                                     cloudflare_api_key=API_KEY,
                                     cloudflare_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "cloudflare")

        self.mock_client = mock.MagicMock()
        # _get_cloudflare_client | pylint: disable=protected-access
        self.auth._get_cloudflare_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class AuthenticatorInputTest(unittest.TestCase):
    supplied_email = 'fake@example.com'
    supplied_api_key = 'fake-api-key'

    # Not using setUp because the flow is dependent on the test case
    def _setUp(self, email=None, api_key=None):
        from certbot.plugins.dns_cloudflare import Authenticator
        config = mock.MagicMock()
        config.cloudflare_propagation_seconds = 0  # don't wait during tests
        if email:
            config.cloudflare_email = email
        else:
            config.cloudflare_email = None

        if api_key:
            config.cloudflare_api_key = api_key
        else:
            config.cloudflare_api_key = None

        auth = Authenticator(config, "cloudflare")
        return auth

    @test_util.patch_get_utility()
    def test_user_input_email(self, mock_get_utility):
        auth = self._setUp(api_key=API_KEY)

        mock_display = mock_get_utility()
        mock_display.input.return_value = (display_util.OK, self.supplied_email,)

        auth.perform([])

        self.assertEqual(auth.conf('email'), self.supplied_email)
        self.assertEqual(auth.conf('api-key'), API_KEY)

    @test_util.patch_get_utility()
    def test_user_input_api_key(self, mock_get_utility):
        auth = self._setUp(email=EMAIL)

        mock_display = mock_get_utility()
        mock_display.input.return_value = (display_util.OK, self.supplied_api_key,)

        auth.perform([])

        self.assertEqual(auth.conf('email'), EMAIL)
        self.assertEqual(auth.conf('api-key'), self.supplied_api_key)

    @test_util.patch_get_utility()
    def test_user_input_both(self, mock_get_utility):
        auth = self._setUp()

        mock_display = mock_get_utility()
        mock_display.input.side_effect = [(display_util.OK, self.supplied_email,),
                                          (display_util.OK, self.supplied_api_key,)]

        auth.perform([])

        self.assertEqual(auth.conf('email'), self.supplied_email)
        self.assertEqual(auth.conf('api-key'), self.supplied_api_key)

    @test_util.patch_get_utility()
    def test_user_input_email_cancel(self, mock_get_utility):
        auth = self._setUp(api_key=API_KEY)

        mock_display = mock_get_utility()
        mock_display.input.side_effect = [(display_util.CANCEL, "C",),]

        self.assertRaises(errors.PluginError, auth.perform, [])

    @test_util.patch_get_utility()
    def test_user_input_api_key_cancel(self, mock_get_utility):
        auth = self._setUp(email=EMAIL)

        mock_display = mock_get_utility()
        mock_display.input.side_effect = [(display_util.CANCEL, "C",),]

        self.assertRaises(errors.PluginError, auth.perform, [])


class CloudflareClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42
    zone_id = 1
    record_id = 2

    def setUp(self):
        from certbot.plugins.dns_cloudflare import _CloudflareClient

        self.cloudflare_client = _CloudflareClient(EMAIL, API_KEY)

        self.cf = mock.MagicMock()
        self.cloudflare_client.cf = self.cf

    def test_add_txt_record(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]

        self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                              self.record_ttl)

        self.cf.zones.dns_records.post.assert_called_with(self.zone_id, data=mock.ANY)

        post_data = self.cf.zones.dns_records.post.call_args[1]['data']

        self.assertEqual('TXT', post_data['type'])
        self.assertEqual(self.record_name, post_data['name'])
        self.assertEqual(self.record_content, post_data['content'])
        self.assertEqual(self.record_ttl, post_data['ttl'])

    def test_add_txt_record_error(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]

        self.cf.zones.dns_records.post.side_effect = API_ERROR

        self.assertRaises(
            errors.PluginError,
            self.cloudflare_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_error_during_zone_lookup(self):
        self.cf.zones.get.side_effect = API_ERROR

        self.assertRaises(
            errors.PluginError,
            self.cloudflare_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_zone_not_found(self):
        self.cf.zones.get.return_value = []

        self.assertRaises(
            errors.PluginError,
            self.cloudflare_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.return_value = [{'id': self.record_id}]

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY),
                    mock.call.zones.dns_records.delete(self.zone_id, self.record_id)]

        self.assertEqual(expected, self.cf.mock_calls)

        get_data = self.cf.zones.dns_records.get.call_args[1]['params']

        self.assertEqual('TXT', get_data['type'])
        self.assertEqual(self.record_name, get_data['name'])
        self.assertEqual(self.record_content, get_data['content'])

    def test_del_txt_record_error_during_zone_lookup(self):
        self.cf.zones.get.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_during_delete(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.return_value = [{'id': self.record_id}]
        self.cf.zones.dns_records.delete.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY),
                    mock.call.zones.dns_records.delete(self.zone_id, self.record_id)]

        self.assertEqual(expected, self.cf.mock_calls)

    def test_del_txt_record_error_during_get(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY)]

        self.assertEqual(expected, self.cf.mock_calls)

    def test_del_txt_record_no_record(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.return_value = []

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY)]

        self.assertEqual(expected, self.cf.mock_calls)

    def test_del_txt_record_no_zone(self):
        self.cf.zones.get.return_value = [{'id': None}]

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY)]

        self.assertEqual(expected, self.cf.mock_calls)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
