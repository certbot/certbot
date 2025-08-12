"""Tests for certbot_dns_cloudflare._internal.dns_cloudflare."""

import sys
import unittest
from unittest import mock

import CloudFlare
import pytest
import dns.exception

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
        # workaround for wont-fix https://github.com/python/mypy/issues/2427 that works with
        # both strict and non-strict mypy
        setattr(self.auth, '_get_cloudflare_client', mock.MagicMock(return_value=self.mock_client))

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    @test_util.patch_display_util()
    def test_api_token(self, unused_mock_get_utility):
        dns_test_common.write({"cloudflare_api_token": API_TOKEN},
                              self.config.cloudflare_credentials)
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_no_creds(self):
        dns_test_common.write({}, self.config.cloudflare_credentials)
        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    def test_missing_email_or_key(self):
        dns_test_common.write({"cloudflare_api_key": API_KEY}, self.config.cloudflare_credentials)
        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

        dns_test_common.write({"cloudflare_email": EMAIL}, self.config.cloudflare_credentials)
        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    def test_email_or_key_with_token(self):
        dns_test_common.write({"cloudflare_api_token": API_TOKEN, "cloudflare_email": EMAIL},
                              self.config.cloudflare_credentials)
        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

        dns_test_common.write({"cloudflare_api_token": API_TOKEN, "cloudflare_api_key": API_KEY},
                              self.config.cloudflare_credentials)
        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

        dns_test_common.write({"cloudflare_api_token": API_TOKEN, "cloudflare_email": EMAIL,
                               "cloudflare_api_key": API_KEY}, self.config.cloudflare_credentials)
        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    def test_check_cname_flag_initialization(self):
        from certbot_dns_cloudflare._internal.dns_cloudflare import Authenticator

        dns_test_common.write({"cloudflare_email": EMAIL, "cloudflare_api_key": API_KEY,
                              "cloudflare_check_cname": "true"},
                              self.config.cloudflare_credentials)

        auth = Authenticator(self.config, "cloudflare")
        auth._setup_credentials()
        assert auth._get_cloudflare_client().check_cname is True

        dns_test_common.write({"cloudflare_api_token": API_TOKEN,
                              "cloudflare_check_cname": "true"},
                              self.config.cloudflare_credentials)
        auth = Authenticator(self.config, "cloudflare")
        auth._setup_credentials()
        assert auth._get_cloudflare_client().check_cname is True

        dns_test_common.write({"cloudflare_email": EMAIL, "cloudflare_api_key": API_KEY,
                              "cloudflare_check_cname": "false"},
                              self.config.cloudflare_credentials)
        auth = Authenticator(self.config, "cloudflare")
        auth._setup_credentials()
        assert auth._get_cloudflare_client().check_cname is False

        dns_test_common.write({"cloudflare_email": EMAIL, "cloudflare_api_key": API_KEY},
                              self.config.cloudflare_credentials)
        auth = Authenticator(self.config, "cloudflare")
        auth._setup_credentials()
        assert auth._get_cloudflare_client().check_cname is False

        dns_test_common.write({"cloudflare_email": EMAIL, "cloudflare_api_key": API_KEY,
                               "cloudflare_check_cname": "some_other_value"},
                              self.config.cloudflare_credentials)
        auth = Authenticator(self.config, "cloudflare")
        auth._setup_credentials()
        assert auth._get_cloudflare_client().check_cname is False


class CloudflareClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42
    zone_id = str(1)
    record_id = str(2)

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

        assert 'TXT' == post_data['type']
        assert self.record_name == post_data['name']
        assert self.record_content == post_data['content']
        assert self.record_ttl == post_data['ttl']

    def test_add_txt_record_error(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]

        self.cf.zones.dns_records.post.side_effect = CloudFlare.exceptions.CloudFlareAPIError(1009, '', '')

        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_error_during_zone_lookup(self):
        self.cf.zones.get.side_effect = API_ERROR

        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_zone_not_found(self):
        self.cf.zones.get.return_value = []

        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_bad_creds(self):
        self.cf.zones.get.side_effect = CloudFlare.exceptions.CloudFlareAPIError(6003, '', '')
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.cf.zones.get.side_effect = CloudFlare.exceptions.CloudFlareAPIError(9103, '', '')
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.cf.zones.get.side_effect = CloudFlare.exceptions.CloudFlareAPIError(9109, '', '')
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.cf.zones.get.side_effect = CloudFlare.exceptions.CloudFlareAPIError(0, 'com.cloudflare.api.account.zone.list', '')
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.return_value = [{'id': self.record_id}]

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY),
                    mock.call.zones.dns_records.delete(self.zone_id, self.record_id)]

        assert expected == self.cf.mock_calls

        get_data = self.cf.zones.dns_records.get.call_args[1]['params']

        assert 'TXT' == get_data['type']
        assert self.record_name == get_data['name']
        assert self.record_content == get_data['content']

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

        assert expected == self.cf.mock_calls

    def test_del_txt_record_error_during_get(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY)]

        assert expected == self.cf.mock_calls

    def test_del_txt_record_no_record(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.return_value = []

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY)]

        assert expected == self.cf.mock_calls

    def test_del_txt_record_no_zone(self):
        self.cf.zones.get.return_value = [{'id': None}]

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY)]

        assert expected == self.cf.mock_calls

    @mock.patch('certbot_dns_cloudflare._internal.dns_cloudflare.dns.resolver')
    def test_find_target_with_cname(self, mock_dns_resolver):
        # Configure the client to check CNAME records
        self.cloudflare_client = self.cloudflare_client.__class__(EMAIL, API_KEY, check_cname='true')
        self.cloudflare_client.cf = self.cf

        # Mock the DNS resolver to return a CNAME record
        mock_dns_resolver.resolve.return_value = [mock.MagicMock(target='cname.example.com')]
        self.cf.zones.get.return_value = [{'id': self.zone_id}]

        target = self.cloudflare_client._find_target(DOMAIN, self.record_name)

        # Verify that dns.resolver.resolve was called for the original record_name
        mock_dns_resolver.resolve.assert_called_with(self.record_name, 'CNAME')
        # Verify that the zone lookup was done with the CNAME target
        self.cf.zones.get.assert_called_with(params={'name': 'cname.example.com', 'per_page': 1})
        # Verify that the returned target has the CNAME target as record_name
        assert target.record_name == 'cname.example.com'
        assert target.zone_id == self.zone_id

    @mock.patch('certbot_dns_cloudflare._internal.dns_cloudflare.dns.resolver')
    def test_find_target_no_cname(self, mock_dns_resolver):
        # Configure the client to check CNAME records
        self.cloudflare_client = self.cloudflare_client.__class__(EMAIL, API_KEY, check_cname='true')
        self.cloudflare_client.cf = self.cf

        # Mock the DNS resolver to raise an exception (no CNAME found)
        mock_dns_resolver.resolve.side_effect = dns.exception.DNSException
        self.cf.zones.get.return_value = [{'id': self.zone_id}]

        target = self.cloudflare_client._find_target(DOMAIN, self.record_name)

        # Verify that dns.resolver.resolve was called
        mock_dns_resolver.resolve.assert_called_with(self.record_name, 'CNAME')
        # Verify that the zone lookup was done with the original domain name
        self.cf.zones.get.assert_called_with(params={'name': DOMAIN, 'per_page': 1})
        # Verify that the returned target has the original record_name
        assert target.record_name == self.record_name
        assert target.zone_id == self.zone_id


class CloudflareClientTargetTest(unittest.TestCase):

    def setUp(self):
        from certbot_dns_cloudflare._internal.dns_cloudflare import _CloudflareClientTarget
        self.cloudflare_client_target_class = _CloudflareClientTarget

    def test_cloudflare_client_target_str(self):
        # Create an instance with a known zone_id
        target = self.cloudflare_client_target_class(zone_id='test_zone_id_123', record_name='test_record')
        assert str(target) == 'test_zone_id_123'

        # Create an instance with an empty zone_id
        target_empty = self.cloudflare_client_target_class(zone_id='', record_name='test_record_empty')
        assert str(target_empty) == ''


    def test_cloudflare_client_target_bool(self):
        # Test case where zone_id is a non-empty string
        target_true = self.cloudflare_client_target_class(zone_id='test_zone_id_abc', record_name='test_record')
        assert bool(target_true) is True

        # Test case where zone_id is an empty string
        target_false_empty = self.cloudflare_client_target_class(zone_id='', record_name='test_record_empty')
        assert bool(target_false_empty) is False


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover