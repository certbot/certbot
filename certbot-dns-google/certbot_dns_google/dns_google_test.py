"""Tests for certbot_dns_google.dns_google."""

import os
import unittest

import mock
from googleapiclient.errors import Error

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

ACCOUNT_JSON_PATH = '/not/a/real/path.json'
API_ERROR = Error()
PROJECT_ID = "test-test-1"


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_google.dns_google import Authenticator

        path = os.path.join(self.tempdir, 'file.json')
        open(path, "wb").close()

        super(AuthenticatorTest, self).setUp()
        self.config = mock.MagicMock(google_credentials=path,
                                     google_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "google")

        self.mock_client = mock.MagicMock()
        # _get_google_client | pylint: disable=protected-access
        self.auth._get_google_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class GoogleClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42
    zone = "ZONE_ID"
    change = "an-id"

    def _setUp_client_with_mock(self, zone_request_side_effect):
        from certbot_dns_google.dns_google import _GoogleClient

        client = _GoogleClient(ACCOUNT_JSON_PATH)

        # Setup
        mock_mz = mock.MagicMock()
        mock_mz.list.return_value.execute.side_effect = zone_request_side_effect

        mock_changes = mock.MagicMock()

        client.dns.managedZones = mock.MagicMock(return_value=mock_mz)
        client.dns.changes = mock.MagicMock(return_value=mock_changes)

        return client, mock_changes

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record(self, unused_credential_mock):
        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone}]}])

        client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        expected_body = {
            "kind": "dns#change",
            "additions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": self.record_name + ".",
                    "rrdatas": [self.record_content, ],
                    "ttl": self.record_ttl,
                },
            ],
        }

        changes.create.assert_called_with(body=expected_body,
                                               managedZone=self.zone,
                                               project=PROJECT_ID)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_and_poll(self, unused_credential_mock):
        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone}]}])
        changes.create.return_value.execute.return_value = {'status': 'pending', 'id': self.change}
        changes.get.return_value.execute.return_value = {'status': 'done'}

        client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        changes.create.assert_called_with(body=mock.ANY,
                                               managedZone=self.zone,
                                               project=PROJECT_ID)

        changes.get.assert_called_with(changeId=self.change,
                                            managedZone=self.zone,
                                            project=PROJECT_ID)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_error_during_zone_lookup(self, unused_credential_mock):
        client, unused_changes = self._setUp_client_with_mock(API_ERROR)

        self.assertRaises(errors.PluginError, client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content, self.record_ttl)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_zone_not_found(self, unused_credential_mock):
        client, unused_changes = self._setUp_client_with_mock([{'managedZones': []},
                                                               {'managedZones': []}])

        self.assertRaises(errors.PluginError, client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content, self.record_ttl)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_error_during_add(self, unused_credential_mock):
        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone}]}])
        changes.create.side_effect = API_ERROR

        self.assertRaises(errors.PluginError, client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content, self.record_ttl)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_del_txt_record(self, unused_credential_mock):
        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone}]}])

        client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        expected_body = {
            "kind": "dns#change",
            "deletions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": self.record_name + ".",
                    "rrdatas": [self.record_content, ],
                    "ttl": self.record_ttl,
                },
            ],
        }

        changes.create.assert_called_with(body=expected_body,
                                               managedZone=self.zone,
                                               project=PROJECT_ID)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_del_txt_record_error_during_zone_lookup(self, unused_credential_mock):
        client, unused_changes = self._setUp_client_with_mock(API_ERROR)

        client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_del_txt_record_zone_not_found(self, unused_credential_mock):
        client, unused_changes = self._setUp_client_with_mock([{'managedZones': []},
                                                               {'managedZones': []}])

        client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_del_txt_record_error_during_delete(self, unused_credential_mock):
        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone}]}])
        changes.create.side_effect = API_ERROR

        client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
