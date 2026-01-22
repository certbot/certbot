"""Tests for certbot_dns_cloudflare._internal.dns_cloudflare."""

import sys
import unittest
from unittest import mock
from dataclasses import dataclass

from cloudflare import Cloudflare, APIError

import pytest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_ERROR = APIError('', request='', body={'errors': [{'code': 1000}]})

API_TOKEN = 'an-api-token'

API_KEY = 'an-api-key'
EMAIL = 'example@example.com'


@dataclass
class CFResultList(object):
    result: list

@dataclass
class CFListObject(object):
    id: str

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
        self.cf.zones.list.return_value = CFResultList(result=[CFListObject(id=self.zone_id)])

        self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                              self.record_ttl)


        self.cf.dns.records.create.assert_called_with(zone_id=self.zone_id, type=mock.ANY, name=mock.ANY, content=mock.ANY, ttl=mock.ANY)

        post_data = self.cf.dns.records.create.call_args.kwargs

        assert 'TXT' == post_data['type']
        assert self.record_name == post_data['name']
        assert self.record_content == post_data['content']
        assert self.record_ttl == post_data['ttl']

    def test_add_txt_record_error(self):
        self.cf.zones.list.return_value = CFResultList(result=[CFListObject(id=self.zone_id)])

        self.cf.dns.records.create.side_effect = APIError('', request='', body={'errors': [{'code': 1009}]})

        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_error_during_zone_lookup(self):
        self.cf.zones.list.side_effect = API_ERROR

        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_zone_not_found(self):
        self.cf.zones.list.return_value = []

        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_bad_creds(self):
        self.cf.zones.list.side_effect = APIError('', request='', body={'errors': [{'code': 6003}]})
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.cf.zones.list.side_effect = APIError('', request='', body={'errors': [{'code': 9103}]})
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.cf.zones.list.side_effect = APIError('', request='', body={'errors': [{'code': 9109}]})
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.cf.zones.list.side_effect = APIError('', request='', body={'errors': [{'code': 9109, 'status': 'com.cloudflare.api.account.zone.list'}]})
        with pytest.raises(errors.PluginError):
            self.cloudflare_client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record(self):
        self.cf.zones.list.return_value = CFResultList(result=[CFListObject(id=self.zone_id)])
        self.cf.dns.records.list.return_value = CFResultList(result=[CFListObject(id=self.record_id)])

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        expected = [mock.call.zones.list(name=mock.ANY, per_page=mock.ANY),
                    mock.call.dns.records.list(zone_id=mock.ANY, type=mock.ANY, name=mock.ANY, content=mock.ANY, per_page=mock.ANY),
                    mock.call.dns.records.delete(1, 2)]

        assert expected == self.cf.mock_calls

        get_data = self.cf.dns.records.list.call_args.kwargs

        assert 'TXT' == get_data['type']
        assert self.record_name == get_data['name']
        assert self.record_content == get_data['content']

    def test_del_txt_record_error_during_zone_lookup(self):
        self.cf.zones.list.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_during_delete(self):
        self.cf.zones.list.return_value = CFResultList(result=[CFListObject(id=self.zone_id)])
        self.cf.zones.dns_records.get.return_value = CFResultList(result=[CFListObject(id=self.record_id)])
        self.cf.zones.dns_records.delete.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.list(name=mock.ANY, per_page=mock.ANY),
                    mock.call.dns.records.list(zone_id=mock.ANY, type=mock.ANY, name=mock.ANY, content=mock.ANY, per_page=mock.ANY),
                    mock.call.dns.records.list(zone_id=mock.ANY, type=mock.ANY, name=mock.ANY, content=mock.ANY, per_page=mock.ANY).result.__len__()
                    ]
        assert expected == self.cf.mock_calls

    def test_del_txt_record_error_during_get(self):
        self.cf.zones.list.return_value = CFResultList(result=[CFListObject(id=self.zone_id)])
        self.cf.zones.dns_records.get.side_effect = API_ERROR

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.list(name=mock.ANY, per_page=mock.ANY),
                    mock.call.dns.records.list(zone_id=mock.ANY, type=mock.ANY, name=mock.ANY, content=mock.ANY, per_page=mock.ANY),
                    mock.call.dns.records.list(zone_id=mock.ANY, type=mock.ANY, name=mock.ANY, content=mock.ANY, per_page=mock.ANY).result.__len__()
                    ]

        assert expected == self.cf.mock_calls

    def test_del_txt_record_no_record(self):
        self.cf.zones.list.return_value = CFResultList(result=[CFListObject(id=self.zone_id)])
        self.cf.dns.records.list.return_value = CFResultList(result=[])

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        expected = [mock.call.zones.list(name=mock.ANY, per_page=mock.ANY),
                    mock.call.dns.records.list(zone_id=mock.ANY, type=mock.ANY, name=mock.ANY, content=mock.ANY, per_page=mock.ANY)
                    ]

        assert expected == self.cf.mock_calls

    def test_del_txt_record_no_zone(self):
        self.cf.zones.list.return_value = CFResultList(result=[])

        self.cloudflare_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        # There are 2 mocks for the fqdn and the base domain - Needs fixed if the subdomain is longer
        expected = []
        for dom in DOMAIN.split('.'):
            expected.append(mock.call.zones.list(name=mock.ANY, per_page=mock.ANY))

        assert expected == self.cf.mock_calls


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
