"""Tests for certbot_dns_azure.dns_azure."""

import os
import unittest

import mock
import json

from certbot import errors
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util
from requests import Response

from msrestazure.azure_exceptions import CloudError


RESOURCE_GROUP = 'test-test-1'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        from certbot_dns_azure.dns_azure import Authenticator

        super(AuthenticatorTest, self).setUp()

        config_path = AzureClientConfigDummy.build_config(self.tempdir)

        self.config = mock.MagicMock(azure_credentials=config_path,
                                     azure_resource_group=RESOURCE_GROUP)

        self.auth = Authenticator(self.config, "azure")

        self.mock_client = mock.MagicMock()
        # pylint: disable=protected-access
        self.auth._get_azure_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record('_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record('_acme-challenge.'+DOMAIN)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class AzureClientTest(test_util.TempDirTestCase):
    zone = "foo.com"
    record_name = "bar"
    record_content = "baz"
    record_ttl = 42

    def _getCloudError(self):
        response = Response()
        response.status_code = 500
        return CloudError(response)

    def setUp(self):
        from certbot_dns_azure.dns_azure import _AzureClient
        super(AzureClientTest, self).setUp()

        config_path = AzureClientConfigDummy.build_config(self.tempdir)

        self.azure_client = _AzureClient(RESOURCE_GROUP, config_path)

        self.dns_client = mock.MagicMock()
        self.azure_client.dns_client = self.dns_client
        # pylint: disable=protected-access
        self.azure_client._find_managed_zone = mock.MagicMock()

    def test_add_txt_record(self):
        # pylint: disable=protected-access
        self.azure_client._find_managed_zone.return_value = self.zone

        self.azure_client.add_txt_record(self.record_name + "." + self.zone,
                                         self.record_content,
                                         self.record_ttl)

        self.dns_client.record_sets.create_or_update.assert_called_with(
                                        self.azure_client.resource_group,
                                        self.zone,
                                        self.record_name,
                                        'TXT',
                                        mock.ANY)

        record = self.dns_client.record_sets.create_or_update.call_args[0][4]

        self.assertEqual(self.record_ttl, record.ttl)
        self.assertEqual([self.record_content], record.txt_records[0].value)

    def test_add_txt_record_error(self):
        # pylint: disable=protected-access
        self.azure_client._find_managed_zone.return_value = self.zone

        self.dns_client.record_sets.create_or_update.side_effect = self._getCloudError()

        with self.assertRaises(errors.PluginError):
            self.azure_client.add_txt_record(self.record_name + "." + self.zone,
                                             self.record_content,
                                             self.record_ttl)

    def test_add_txt_record_zone_not_found(self):
        # pylint: disable=protected-access
        self.azure_client._find_managed_zone.return_value = None
        # pylint: disable=protected-access
        self.azure_client._find_managed_zone.side_effect = self._getCloudError()

        with self.assertRaises(errors.PluginError):
            self.azure_client.add_txt_record(self.record_name + "." + self.zone,
                                             self.record_content,
                                             self.record_ttl)

    def test_del_txt_record(self):
        # pylint: disable=protected-access
        self.azure_client._find_managed_zone.return_value = self.zone

        self.azure_client.del_txt_record(self.record_name + "." + self.zone)

        self.dns_client.record_sets.delete.assert_called_with(self.azure_client.resource_group,
                                                              self.zone,
                                                              self.record_name,
                                                              'TXT')
    def test_del_txt_record_no_zone(self):
        # pylint: disable=protected-access
        self.azure_client._find_managed_zone.return_value = None
        # pylint: disable=protected-access
        self.azure_client._find_managed_zone.side_effect = self._getCloudError()

        self.azure_client.del_txt_record(self.record_name + "." + self.zone)

        self.dns_client.record_sets.delete.assert_not_called()


class AzureClientConfigDummy(object):
    """Helper class to create dummy Azure configuration"""

    @classmethod
    def build_config(cls, tempdir):
        """Helper method to create dummy Azure configuration"""

        config_path = os.path.join(tempdir, 'azurecreds.json')
        with open(config_path, 'w') as outfile:
            json.dump({
                "clientId": "uuid",
                "clientSecret": "uuid",
                "subscriptionId": "uuid",
                "tenantId": "uuid",
                "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
                "resourceManagerEndpointUrl": "https://management.azure.com/",
                "activeDirectoryGraphResourceId": "https://graph.windows.net/",
                "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
                "galleryEndpointUrl": "https://gallery.azure.com/",
                "managementEndpointUrl": "https://management.core.windows.net/"
            }, outfile)

        os.chmod(config_path, 0o600)

        return config_path

if __name__ == "__main__":
    unittest.main()  # pragma: no cover

