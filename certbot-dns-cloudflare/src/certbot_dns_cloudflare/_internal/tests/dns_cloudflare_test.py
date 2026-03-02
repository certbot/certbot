"""Tests for certbot_dns_cloudflare._internal.dns_cloudflare."""

import sys
import unittest
from unittest import mock

import cloudflare
import httpx
import pytest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util


def _make_api_error(cf_code, msg='', http_status=400):
    """Build a cloudflare.APIStatusError with a Cloudflare error code in the body."""
    body = {'success': False, 'errors': [{'code': cf_code, 'message': msg}]}
    response = httpx.Response(http_status, json=body,
                              request=httpx.Request('GET', 'https://api.cloudflare.com'))
    return cloudflare.APIStatusError(message=msg or str(cf_code), response=response, body=body)


API_ERROR = _make_api_error(1000)

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


def _mock_zone(zone_id):
    """Create a mock zone object with an .id attribute."""
    zone = mock.MagicMock()
    zone.id = zone_id
    return zone


def _mock_record(record_id):
    """Create a mock DNS record object with an .id attribute."""
    record = mock.MagicMock()
    record.id = record_id
    return record


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
        self.cf.zones.list.return_value = [_mock_zone(self.zone_id)]

        self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                              self.record_ttl)

        self.cf.dns.records.create.assert_called_with(
            zone_id=self.zone_id, type='TXT', name=self.record_name,
            content=self.record_content, ttl=self.record_ttl)

    def test_add_txt_record_error(self):
        self.cf.zones.list.return_value = [_mock_zone(self.zone_id)]

        self.cf.dns.records.create.side_effect = _make_api_error(1009)

        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                                  self.record_ttl)

    def test_add_txt_record_error_during_zone_lookup(self):
        self.cf.zones.list.side_effect = API_ERROR

        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                                  self.record_ttl)

    def test_add_txt_record_zone_not_found(self):
        self.cf.zones.list.return_value = []

        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                                  self.record_ttl)

    def test_add_txt_record_bad_creds(self):
        self.cf.zones.list.side_effect = _make_api_error(6003)
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                                  self.record_ttl)

        self.cf.zones.list.side_effect = _make_api_error(9103)
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                                  self.record_ttl)

        self.cf.zones.list.side_effect = _make_api_error(9109)
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                                  self.record_ttl)

        self.cf.zones.list.side_effect = _make_api_error(0, 'com.cloudflare.api.account.zone.list')
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                                  self.record_ttl)

    def test_del_txt_record(self):
        self.cf.zones.list.return_value = [_mock_zone(self.zone_id)]
        self.cf.dns.records.list.return_value = [_mock_record(self.record_id)]

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.cf.zones.list.assert_called_once()
        self.cf.dns.records.list.assert_called_once_with(
            zone_id=self.zone_id, type='TXT', name=self.record_name,
            content=self.record_content, per_page=1)
        self.cf.dns.records.delete.assert_called_once_with(
            dns_record_id=self.record_id, zone_id=self.zone_id)

    def test_del_txt_record_error_during_zone_lookup(self):
        self.cf.zones.list.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_during_delete(self):
        self.cf.zones.list.return_value = [_mock_zone(self.zone_id)]
        self.cf.dns.records.list.return_value = [_mock_record(self.record_id)]
        self.cf.dns.records.delete.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.cf.dns.records.delete.assert_called_once_with(
            dns_record_id=self.record_id, zone_id=self.zone_id)

    def test_del_txt_record_error_during_get(self):
        self.cf.zones.list.return_value = [_mock_zone(self.zone_id)]
        self.cf.dns.records.list.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.cf.dns.records.list.assert_called_once()
        self.cf.dns.records.delete.assert_not_called()

    def test_del_txt_record_no_record(self):
        self.cf.zones.list.return_value = [_mock_zone(self.zone_id)]
        self.cf.dns.records.list.return_value = []

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.cf.dns.records.list.assert_called_once()
        self.cf.dns.records.delete.assert_not_called()

    def test_del_txt_record_no_zone(self):
        self.cf.zones.list.return_value = [_mock_zone(None)]

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.cf.zones.list.assert_called_once()


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
