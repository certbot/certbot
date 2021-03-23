"""Tests for certbot_dns_cloudflare._internal.dns_cloudflare."""

import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore

from certbot import errors
from certbot.compat import os
from certbot import achallenges
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import KEY
from certbot.tests import util as test_util, acme_util

from azure.mgmt.dns.models import RecordSet, TxtRecord

MULTI_DOMAIN = [
    achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.DNS01, domain='example.com', account_key=KEY),
    achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.DNS01, domain='example.org', account_key=KEY)
]
SINGLE_DOMAIN = [
    achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.DNS01, domain='example.com', account_key=KEY),
]


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_azure._internal.dns_azure import Authenticator

        super(AuthenticatorTest, self).setUp()

        # Setup config files
        config_files = (
            ('sp.ini', {
                'azure_sp_client_id': '912ce44a-0156-4669-ae22-c16a17d34ca5',
                'azure_sp_client_secret': 'E-xqXU83Y-jzTI6xe9fs2YC~mck3ZzUih9',
                'azure_tenant_id': 'ed1090f3-ab18-4b12-816c-599af8a88cf7',
                'azure_zone1': 'example.com:/subscriptions/c135abce-d87d-48df-936c-15596c6968a5/resourceGroups/dns1',
                'azure_zone2': 'example.org:/subscriptions/99800903-fb14-4992-9aff-12eaf2744622/resourceGroups/dns2'
            }),
            ('user_assigned_msi.ini', {
                'azure_msi_client_id': '912ce44a-0156-4669-ae22-c16a17d34ca5',
                'azure_zone1': 'example.com:/subscriptions/c135abce-d87d-48df-936c-15596c6968a5/resourceGroups/dns1',
                'azure_zone2': 'example.org:/subscriptions/99800903-fb14-4992-9aff-12eaf2744622/resourceGroups/dns2'
            }),
            ('system_msi.ini', {
                'azure_msi_system_assigned': 'true',
                'azure_zone1': 'example.com:/subscriptions/c135abce-d87d-48df-936c-15596c6968a5/resourceGroups/dns1',
                'azure_zone2': 'example.org:/subscriptions/99800903-fb14-4992-9aff-12eaf2744622/resourceGroups/dns2'
            })
        )
        for file, config in config_files:
            dns_test_common.write(config, os.path.join(self.tempdir, file))

        self.sp_config = mock.MagicMock(
            azure_config=os.path.join(self.tempdir, 'sp.ini'),
            azure_propagation_seconds=0)
        self.umsi_config = mock.MagicMock(
            azure_config=os.path.join(self.tempdir, 'user_assigned_msi.ini'),
            azure_propagation_seconds=0)
        self.smsi_config = mock.MagicMock(
            azure_config=os.path.join(self.tempdir, 'system_msi.ini'),
            azure_propagation_seconds=0)

        self.auth = Authenticator(self.sp_config, "azure")
        self.mock_credentials = mock.MagicMock()
        self.mock_client = mock.MagicMock()
        self.auth._get_azure_credentials = mock.MagicMock(return_value=self.mock_credentials)
        self.auth._get_azure_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform_multidomain(self):
        self.mock_client.record_sets.get.return_value = RecordSet(txt_records=[])

        # Extract zone TXT record name and value
        zone1_req, zone2_req = MULTI_DOMAIN
        zone1_domain_name = zone1_req.validation_domain_name(zone1_req.domain)
        zone1_key = zone1_req.validation(zone1_req.account_key)
        zone2_domain_name = zone2_req.validation_domain_name(zone2_req.domain)
        zone2_key = zone2_req.validation(zone2_req.account_key)

        self.auth.perform(MULTI_DOMAIN)

        # Check azure client call counts
        self.assertEqual(self.mock_client.record_sets.get.call_count, 2)
        self.assertEqual(self.mock_client.record_sets.create_or_update.call_count, 2)

        #
        zone1_call, zone2_call = self.mock_client.record_sets.create_or_update.call_args_list
        self.assertEqual(zone1_call[1]['zone_name'], "example.com")
        self.assertEqual(zone1_call[1]['record_type'], "TXT")
        self.assertEqual(zone1_call[1]['relative_record_set_name'], zone1_domain_name)
        zone1_txt_records = zone1_call[1]['parameters'].txt_records
        self.assertEqual(len(zone1_txt_records), 1)
        self.assertEqual(zone1_txt_records[0].value[0], zone1_key)

        self.assertEqual(zone2_call[1]['zone_name'], "example.org")
        self.assertEqual(zone2_call[1]['relative_record_set_name'], zone2_domain_name)
        zone2_txt_records = zone2_call[1]['parameters'].txt_records
        self.assertEqual(len(zone2_txt_records), 1)
        self.assertEqual(zone2_txt_records[0].value[0], zone2_key)

    def test_perform_existing(self):
        self.mock_client.record_sets.get.return_value = RecordSet(txt_records=[
            TxtRecord(value=['someexistingkey'])
        ])

        # Extract zone TXT record name and value
        zone1_req = SINGLE_DOMAIN[0]
        zone1_domain_name = zone1_req.validation_domain_name(zone1_req.domain)
        zone1_key = zone1_req.validation(zone1_req.account_key)

        self.auth.perform(SINGLE_DOMAIN)

        # Check azure client call counts
        self.assertEqual(self.mock_client.record_sets.get.call_count, 1)
        self.assertEqual(self.mock_client.record_sets.create_or_update.call_count, 1)

        #
        expected = [self.mock_client.record_sets.create_or_update.call(
            resource_group_name='dns1',
            zone_name='example.com',
            relative_record_set_name=zone1_domain_name,
            parameters=RecordSet(txt_records=TxtRecord(value=[zone1_key, 'someexistingkey']))
        )]
        zone1_call = self.mock_client.record_sets.create_or_update.call_args_list[0]
        self.assertEqual(zone1_call[1]['zone_name'], "example.com")
        self.assertEqual(zone1_call[1]['record_type'], "TXT")
        self.assertEqual(zone1_call[1]['relative_record_set_name'], zone1_domain_name)
        zone1_txt_records = zone1_call[1]['parameters'].txt_records

        self.assertEqual(len(zone1_txt_records), 1)
        txt_values = zone1_txt_records[0].value
        self.assertIn(zone1_key, txt_values)
        self.assertIn('someexistingkey', txt_values)

    def test_cleanup_multiple(self):
        self.mock_client.record_sets.get.return_value = RecordSet(txt_records=[])

        # Extract zone TXT record name and value
        zone1_req, zone2_req = MULTI_DOMAIN
        zone1_domain_name = zone1_req.validation_domain_name(zone1_req.domain)
        zone2_domain_name = zone2_req.validation_domain_name(zone2_req.domain)

        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup(MULTI_DOMAIN)

        # Check azure client call counts
        self.assertEqual(self.mock_client.record_sets.get.call_count, 2)
        self.assertEqual(self.mock_client.record_sets.delete.call_count, 2)

        zone1_call, zone2_call = self.mock_client.record_sets.delete.call_args_list
        self.assertEqual(zone1_call[1]['zone_name'], "example.com")
        self.assertEqual(zone1_call[1]['record_type'], "TXT")
        self.assertEqual(zone1_call[1]['relative_record_set_name'], zone1_domain_name)

        self.assertEqual(zone2_call[1]['zone_name'], "example.org")
        self.assertEqual(zone2_call[1]['record_type'], "TXT")
        self.assertEqual(zone2_call[1]['relative_record_set_name'], zone2_domain_name)

    def test_cleanup_existing(self):
        self.mock_client.record_sets.get.return_value = RecordSet(txt_records=[
            TxtRecord(value=['someexistingkey'])
        ])

        # Extract zone TXT record name and value
        zone1_req = SINGLE_DOMAIN[0]
        zone1_domain_name = zone1_req.validation_domain_name(zone1_req.domain)
        zone1_key = zone1_req.validation(zone1_req.account_key)

        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup(SINGLE_DOMAIN)

        # Check azure client call counts
        self.assertEqual(self.mock_client.record_sets.get.call_count, 1)
        self.assertEqual(self.mock_client.record_sets.delete.call_count, 0)
        self.assertEqual(self.mock_client.record_sets.create_or_update.call_count, 1)

        # Check recordset is updated to not include key
        zone1_call = self.mock_client.record_sets.create_or_update.call_args_list[0]
        self.assertEqual(zone1_call[1]['zone_name'], "example.com")
        self.assertEqual(zone1_call[1]['record_type'], "TXT")
        self.assertEqual(zone1_call[1]['relative_record_set_name'], zone1_domain_name)
        zone1_txt_records = zone1_call[1]['parameters'].txt_records

        self.assertEqual(len(zone1_txt_records), 1)
        txt_values = zone1_txt_records[0].value
        self.assertNotIn(zone1_key, txt_values)
        self.assertIn('someexistingkey', txt_values)

    def test_config_missing_auth(self):
        # Test no auth info
        dns_test_common.write({}, self.sp_config.azure_config)
        with self.assertRaises(errors.PluginError) as cm:
            self.auth.perform(SINGLE_DOMAIN)
        self.assertIn('No authentication methods have been configured', cm.exception.args[0])

    def test_config_missing_zone_info(self):
        # Test missing mapping list
        dns_test_common.write({
            'azure_sp_client_id': '912ce44a-0156-4669-ae22-c16a17d34ca5',
            'azure_sp_client_secret': 'E-xqXU83Y-jzTI6xe9fs2YC~mck3ZzUih9',
            'azure_tenant_id': 'ed1090f3-ab18-4b12-816c-599af8a88cf7',
        }, self.sp_config.azure_config)
        with self.assertRaises(errors.PluginError) as cm:
            self.auth.perform(SINGLE_DOMAIN)
        self.assertIn('At least one zone mapping needs to be provided', cm.exception.args[0])

    def test_config_bad_zone_info(self):
        # Test missing mapping list
        dns_test_common.write({
            'azure_sp_client_id': '912ce44a-0156-4669-ae22-c16a17d34ca5',
            'azure_sp_client_secret': 'E-xqXU83Y-jzTI6xe9fs2YC~mck3ZzUih9',
            'azure_tenant_id': 'ed1090f3-ab18-4b12-816c-599af8a88cf7',
            'azure_zone1': 'example.com',
        }, self.sp_config.azure_config)
        with self.assertRaises(errors.PluginError) as cm:
            self.auth.perform(SINGLE_DOMAIN)
        self.assertIn('DNS Zone mapping is not in the format', cm.exception.args[0])


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
