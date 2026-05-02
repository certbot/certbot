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
                                     cloudflare_propagation_seconds=0,  # don't wait during tests
                                     cloudflare_delegate_via=None)

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

    @test_util.patch_display_util()
    def test_delegation_single_domain(self, unused_mock_get_utility):
        self.config.cloudflare_delegate_via = 'acme-zone.org'
        self.auth.perform([self.achall])
        expected = [mock.call.add_txt_record('acme-zone.org', '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    @test_util.patch_display_util()
    def test_delegation_multiple_domains(self, unused_mock_get_utility):
        from certbot import achallenges
        from certbot.tests import acme_util
        from certbot.plugins.dns_test_common import KEY
        # Create second challenge for different domain
        achall2 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.DNS01_P_2, domain='second-domain.com', account_key=KEY)
        self.config.cloudflare_delegate_via = 'acme-zone.org'
        self.auth.perform([self.achall, achall2])
        expected = [
            mock.call.add_txt_record('acme-zone.org', '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY),
            mock.call.add_txt_record('acme-zone.org', '_acme-challenge.second-domain.com', mock.ANY, mock.ANY)
        ]
        assert expected == self.mock_client.mock_calls

    @test_util.patch_display_util()
    def test_delegation_wildcard(self, unused_mock_get_utility):
        from certbot import achallenges
        from certbot.tests import acme_util
        from certbot.plugins.dns_test_common import KEY
        wildcard_achall = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.DNS01_P, domain='*.'+DOMAIN, account_key=KEY)
        self.config.cloudflare_delegate_via = 'acme-zone.org'
        self.auth.perform([wildcard_achall])
        # Wildcard domain creates validation name with *.  - delegation zone is still used
        expected = [mock.call.add_txt_record('acme-zone.org', '_acme-challenge.*.'+DOMAIN, mock.ANY, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_cleanup_with_delegation(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        # delegate_zone | pylint: disable=protected-access
        self.auth.delegate_zone = 'acme-zone.org'
        self.auth.cleanup([self.achall])
        expected = [mock.call.del_txt_record('acme-zone.org', '_acme-challenge.'+DOMAIN, mock.ANY)]
        assert expected == self.mock_client.mock_calls

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


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
