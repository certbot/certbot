"""Tests for certbot_dns_google.dns_google."""

import os
import unittest

import mock
from googleapiclient import discovery
from googleapiclient.errors import Error
from googleapiclient.http import HttpMock
from httplib2 import ServerNotFoundError

from certbot import errors
from certbot.errors import PluginError
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

    @mock.patch('httplib2.Http.request', side_effect=ServerNotFoundError)
    def test_without_auth(self, unused_mock):
        self.config.google_credentials = None
        self.assertRaises(PluginError, self.auth.perform, [self.achall])


class GoogleClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42
    zone = "ZONE_ID"
    change = "an-id"

    def _setUp_client_with_mock(self, zone_request_side_effect):
        from certbot_dns_google.dns_google import _GoogleClient

        pwd = os.path.dirname(__file__)
        rel_path = 'testdata/discovery.json'
        discovery_file = os.path.join(pwd, rel_path)
        http_mock = HttpMock(discovery_file, {'status': '200'})
        dns_api = discovery.build('dns', 'v1', http=http_mock)

        client = _GoogleClient(ACCOUNT_JSON_PATH, dns_api)

        # Setup
        mock_mz = mock.MagicMock()
        mock_mz.list.return_value.execute.side_effect = zone_request_side_effect

        mock_rrs = mock.MagicMock()
        rrsets = {"rrsets": [{"name": "_acme-challenge.example.org.", "type": "TXT",
                              "rrdatas": ["\"example-txt-contents\""]}]}
        mock_rrs.list.return_value.execute.return_value = rrsets
        mock_changes = mock.MagicMock()

        client.dns.managedZones = mock.MagicMock(return_value=mock_mz)
        client.dns.changes = mock.MagicMock(return_value=mock_changes)
        client.dns.resourceRecordSets = mock.MagicMock(return_value=mock_rrs)

        return client, mock_changes

    @mock.patch('googleapiclient.discovery.build')
    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google._GoogleClient.get_project_id')
    def test_client_without_credentials(self, get_project_id_mock, credential_mock,
                                        unused_discovery_mock):
        from certbot_dns_google.dns_google import _GoogleClient
        _GoogleClient(None)
        self.assertFalse(credential_mock.called)
        self.assertTrue(get_project_id_mock.called)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    @mock.patch('certbot_dns_google.dns_google._GoogleClient.get_project_id')
    def test_add_txt_record(self, get_project_id_mock, credential_mock):
        client, changes = self._setUp_client_with_mock([{'managedZones': [{'id': self.zone}]}])
        credential_mock.assert_called_once_with('/not/a/real/path.json', mock.ANY)
        self.assertFalse(get_project_id_mock.called)

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
    def test_add_txt_record_delete_old(self, unused_credential_mock):
        client, changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone}]}])
        mock_get_rrs = "certbot_dns_google.dns_google._GoogleClient.get_existing_txt_rrset"
        with mock.patch(mock_get_rrs) as mock_rrs:
            mock_rrs.return_value = ["sample-txt-contents"]
            client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)
            self.assertTrue(changes.create.called)
            self.assertTrue("sample-txt-contents" in
                changes.create.call_args_list[0][1]["body"]["deletions"][0]["rrdatas"])

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_add_txt_record_noop(self, unused_credential_mock):
        client, changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone}]}])
        client.add_txt_record(DOMAIN, "_acme-challenge.example.org",
                              "example-txt-contents", self.record_ttl)
        self.assertFalse(changes.create.called)

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

        mock_get_rrs = "certbot_dns_google.dns_google._GoogleClient.get_existing_txt_rrset"
        with mock.patch(mock_get_rrs) as mock_rrs:
            mock_rrs.return_value = ["\"sample-txt-contents\"",
                                     "\"example-txt-contents\""]
            client.del_txt_record(DOMAIN, "_acme-challenge.example.org",
                                "example-txt-contents", self.record_ttl)

        expected_body = {
            "kind": "dns#change",
            "deletions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": "_acme-challenge.example.org.",
                    "rrdatas": ["\"sample-txt-contents\"", "\"example-txt-contents\""],
                    "ttl": self.record_ttl,
                },
            ],
            "additions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": "_acme-challenge.example.org.",
                    "rrdatas": ["\"sample-txt-contents\"", ],
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

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_get_existing(self, unused_credential_mock):
        client, unused_changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone}]}])
        # Record name mocked in setUp
        found = client.get_existing_txt_rrset(self.zone, "_acme-challenge.example.org")
        self.assertEqual(found, ["\"example-txt-contents\""])
        not_found = client.get_existing_txt_rrset(self.zone, "nonexistent.tld")
        self.assertEqual(not_found, None)

    @mock.patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name')
    @mock.patch('certbot_dns_google.dns_google.open',
                mock.mock_open(read_data='{"project_id": "' + PROJECT_ID + '"}'), create=True)
    def test_get_existing_fallback(self, unused_credential_mock):
        client, unused_changes = self._setUp_client_with_mock(
            [{'managedZones': [{'id': self.zone}]}])
        # pylint: disable=no-member
        mock_execute = client.dns.resourceRecordSets.return_value.list.return_value.execute
        mock_execute.side_effect = API_ERROR

        rrset = client.get_existing_txt_rrset(self.zone, "_acme-challenge.example.org")
        self.assertFalse(rrset)

    def test_get_project_id(self):
        from certbot_dns_google.dns_google import _GoogleClient

        response = DummyResponse()
        response.status = 200

        with mock.patch('httplib2.Http.request', return_value=(response, 'test-test-1')):
            project_id = _GoogleClient.get_project_id()
            self.assertEqual(project_id, 'test-test-1')

        with mock.patch('httplib2.Http.request', return_value=(response, b'test-test-1')):
            project_id = _GoogleClient.get_project_id()
            self.assertEqual(project_id, 'test-test-1')

        failed_response = DummyResponse()
        failed_response.status = 404

        with mock.patch('httplib2.Http.request',
                        return_value=(failed_response, "some detailed http error response")):
            self.assertRaises(ValueError, _GoogleClient.get_project_id)

        with mock.patch('httplib2.Http.request', side_effect=ServerNotFoundError):
            self.assertRaises(ServerNotFoundError, _GoogleClient.get_project_id)


class DummyResponse(object):
    """
    Dummy object to create a fake HTTPResponse (the actual one requires a socket and we only
     need the status attribute)
    """
    def __init__(self):
        self.status = 200

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
