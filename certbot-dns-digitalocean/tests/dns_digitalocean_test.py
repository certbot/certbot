"""Tests for certbot_dns_digitalocean._internal.dns_digitalocean."""

import sys
import unittest
from unittest import mock

import digitalocean
import pytest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_ERROR = digitalocean.DataReadError()
TOKEN = 'a-token'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_digitalocean._internal.dns_digitalocean import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"digitalocean_token": TOKEN}, path)

        self.config = mock.MagicMock(digitalocean_credentials=path,
                                     digitalocean_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "digitalocean")

        self.mock_client = mock.MagicMock()
        # _get_digitalocean_client | pylint: disable=protected-access
        self.auth._get_digitalocean_client = mock.MagicMock(return_value=self.mock_client)

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, 30)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class DigitalOceanClientTest(unittest.TestCase):

    id_num = 1
    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"
    record_ttl = 60

    def setUp(self):
        from certbot_dns_digitalocean._internal.dns_digitalocean import _DigitalOceanClient

        self.digitalocean_client = _DigitalOceanClient(TOKEN)

        self.manager = mock.MagicMock()
        self.digitalocean_client.manager = self.manager

    def test_add_txt_record(self):
        wrong_domain_mock = mock.MagicMock()
        wrong_domain_mock.name = "other.invalid"
        wrong_domain_mock.create_new_domain_record.side_effect = AssertionError('Wrong Domain')

        domain_mock = mock.MagicMock()
        domain_mock.name = DOMAIN
        domain_mock.create_new_domain_record.return_value = {'domain_record': {'id': self.id_num}}

        self.manager.get_all_domains.return_value = [wrong_domain_mock, domain_mock]

        self.digitalocean_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                                self.record_ttl)

        domain_mock.create_new_domain_record.assert_called_with(type='TXT',
                                                                name=self.record_prefix,
                                                                data=self.record_content,
                                                                ttl=self.record_ttl)

    def test_add_txt_record_fail_to_find_domain(self):
        self.manager.get_all_domains.return_value = []

        self.assertRaises(errors.PluginError,
                          self.digitalocean_client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_error_finding_domain(self):
        self.manager.get_all_domains.side_effect = API_ERROR

        self.assertRaises(errors.PluginError,
                          self.digitalocean_client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_error_creating_record(self):
        domain_mock = mock.MagicMock()
        domain_mock.name = DOMAIN
        domain_mock.create_new_domain_record.side_effect = API_ERROR

        self.manager.get_all_domains.return_value = [domain_mock]

        self.assertRaises(errors.PluginError,
                          self.digitalocean_client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record(self):
        first_record_mock = mock.MagicMock()
        first_record_mock.type = 'TXT'
        first_record_mock.name = "DIFFERENT"
        first_record_mock.data = self.record_content

        correct_record_mock = mock.MagicMock()
        correct_record_mock.type = 'TXT'
        correct_record_mock.name = self.record_prefix
        correct_record_mock.data = self.record_content

        last_record_mock = mock.MagicMock()
        last_record_mock.type = 'TXT'
        last_record_mock.name = self.record_prefix
        last_record_mock.data = "DIFFERENT"

        domain_mock = mock.MagicMock()
        domain_mock.name = DOMAIN
        domain_mock.get_records.return_value = [first_record_mock,
                                                correct_record_mock,
                                                last_record_mock]

        self.manager.get_all_domains.return_value = [domain_mock]

        self.digitalocean_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.assertTrue(correct_record_mock.destroy.called)

        self.assertFalse(first_record_mock.destroy.call_args_list)
        self.assertFalse(last_record_mock.destroy.call_args_list)

    def test_del_txt_record_error_finding_domain(self):
        self.manager.get_all_domains.side_effect = API_ERROR

        self.digitalocean_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_finding_record(self):
        domain_mock = mock.MagicMock()
        domain_mock.name = DOMAIN
        domain_mock.get_records.side_effect = API_ERROR

        self.manager.get_all_domains.return_value = [domain_mock]

        self.digitalocean_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_deleting_record(self):
        record_mock = mock.MagicMock()
        record_mock.type = 'TXT'
        record_mock.name = self.record_prefix
        record_mock.data = self.record_content
        record_mock.destroy.side_effect = API_ERROR

        domain_mock = mock.MagicMock()
        domain_mock.name = DOMAIN
        domain_mock.get_records.return_value = [record_mock]

        self.manager.get_all_domains.return_value = [domain_mock]

        self.digitalocean_client.del_txt_record(DOMAIN, self.record_name, self.record_content)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))  # pragma: no cover
