"""Tests for certbot_dns_godaddy.dns_godaddy."""

import os
import unittest

import godaddypy
import mock

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_ERROR = godaddypy.client.BadResponse('UNABLE_TO_AUTHENTICATE')
KEY = 'a-key'
SECRET = 'a-secret'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_godaddy.dns_godaddy import Authenticator

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"godaddy_key": KEY, "godaddy_secret": SECRET}, path)

        self.config = mock.MagicMock(godaddy_credentials=path,
                                     godaddy_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "godaddy")

        self.mock_client = mock.MagicMock()
        # _get_godaddy_client | pylint: disable=protected-access
        self.auth._get_godaddy_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class GodaddyClientTest(unittest.TestCase):
    id = 1
    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"

    def setUp(self):
        from certbot_dns_godaddy.dns_godaddy import _GodaddyClient

        self.godaddy_client = _GodaddyClient(KEY, SECRET)

        self.client = mock.MagicMock()
        self.godaddy_client.client = self.client

    def test_add_txt_record(self):
        self.client.get_domains.return_value = [DOMAIN]

        self.godaddy_client.add_txt_record(DOMAIN, self.record_name, self.record_content)

        self.client.add_record.assert_called_with(DOMAIN, {'type': 'TXT',
                                                           'name': self.record_prefix,
                                                           'data': self.record_content})

    def test_add_txt_record_fail_to_find_domain(self):
        self.client.get_domains.return_value = []

        self.assertRaises(errors.PluginError,
                          self.godaddy_client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_error_finding_domain(self):
        self.client.get_domains.side_effect = API_ERROR

        self.assertRaises(errors.PluginError,
                          self.godaddy_client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_error_creating_record(self):
        self.client.get_domains.return_value = [DOMAIN]
        self.client.add_record.side_effect = API_ERROR

        self.assertRaises(errors.PluginError,
                          self.godaddy_client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record(self):
        records = [
            {'type': 'TXT', 'name': 'DIFFERENT', 'data': self.record_content},
            {'type': 'TXT', 'name': self.record_prefix, 'data': self.record_content},
            {'type': 'TXT', 'name': self.record_prefix, 'data': 'DIFFERENT'},
        ]

        self.client.get_domains.return_value = [DOMAIN]
        self.client.get_records.return_value = records

        self.godaddy_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.client.delete_records.assert_called_with(DOMAIN, name=self.record_prefix,
                                                              record_type='TXT')

    def test_del_txt_record_error_finding_domain(self):
        self.client.get_domains.side_effect = API_ERROR

        self.godaddy_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_getting_records(self):
        self.client.get_domains.return_value = [DOMAIN]
        self.client.get_records.side_effect = API_ERROR

        self.godaddy_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_deleting_records(self):
        records = [
            {'type': 'TXT', 'name': 'DIFFERENT', 'data': self.record_content},
            {'type': 'TXT', 'name': self.record_prefix, 'data': self.record_content},
            {'type': 'TXT', 'name': self.record_prefix, 'data': 'DIFFERENT'},
        ]

        self.client.get_domains.return_value = [DOMAIN]
        self.client.get_records.return_value = records
        self.client.delete_records.side_effect = API_ERROR

        self.godaddy_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
