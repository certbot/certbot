"""Tests for certbot_dns_cloudflare._internal.dns_cloudflare."""

import sys
import unittest
from unittest import mock

import CloudFlare
import pytest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_ERROR = CloudFlare.exceptions.CloudFlareAPIError(1000, '', '')

API_TOKEN = 'an-api-token'

API_KEY = 'an-api-key'
EMAIL = 'example@example.com'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_cloudflare._internal.dns_cloudflare import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"cloudflare_email": EMAIL, "cloudflare_api_key": API_KEY}, path)

        self.config = mock.MagicMock(cloudflare_credentials=path,
                                     cloudflare_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "cloudflare")

        self.mock_client = mock.MagicMock()
        # _get_cloudflare_client | pylint: disable=protected-access
        self.auth._get_cloudflare_client = mock.MagicMock(return_value=self.mock_client)

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    @test_util.patch_display_util()
    def test_api_token(self, unused_mock_get_utility):
        dns_test_common.write({"cloudflare_api_token": API_TOKEN},
                              self.config.cloudflare_credentials)
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_no_creds(self):
        dns_test_common.write({}, self.config.cloudflare_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    def test_missing_email_or_key(self):
        dns_test_common.write({"cloudflare_api_key": API_KEY}, self.config.cloudflare_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

        dns_test_common.write({"cloudflare_email": EMAIL}, self.config.cloudflare_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    def test_email_or_key_with_token(self):
        dns_test_common.write({"cloudflare_api_token": API_TOKEN, "cloudflare_email": EMAIL},
                              self.config.cloudflare_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

        dns_test_common.write({"cloudflare_api_token": API_TOKEN, "cloudflare_api_key": API_KEY},
                              self.config.cloudflare_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

        dns_test_common.write({"cloudflare_api_token": API_TOKEN, "cloudflare_email": EMAIL,
                               "cloudflare_api_key": API_KEY}, self.config.cloudflare_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])


class CloudflareClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42
    zone_id = 1
    record_id = 2

    def setUp(self):
        from certbot_dns_cloudflare._internal.dns_cloudflare import _CloudflareClient

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

        self.cf.zones.dns_records.post.side_effect = CloudFlare.exceptions.CloudFlareAPIError(1009, '', '')

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

    def test_add_txt_record_bad_creds(self):
        self.cf.zones.get.side_effect = CloudFlare.exceptions.CloudFlareAPIError(6003, '', '')
        self.assertRaises(
            errors.PluginError,
            self.cloudflare_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.cf.zones.get.side_effect = CloudFlare.exceptions.CloudFlareAPIError(9103, '', '')
        self.assertRaises(
            errors.PluginError,
            self.cloudflare_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.cf.zones.get.side_effect = CloudFlare.exceptions.CloudFlareAPIError(9109, '', '')
        self.assertRaises(
            errors.PluginError,
            self.cloudflare_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.cf.zones.get.side_effect = CloudFlare.exceptions.CloudFlareAPIError(0, 'com.cloudflare.api.account.zone.list', '')
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
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
