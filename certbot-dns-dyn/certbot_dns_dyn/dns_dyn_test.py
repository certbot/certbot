"""Tests for certbot_dns_dyn.dns_dyn."""

import os

import unittest
import mock

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.tests import util as test_util

from certbot_dns_dyn.dns_dyn import Authenticator
from certbot_dns_dyn.dns_dyn import rrem

from dyn.tm.errors import DynectAuthError
from dyn.tm.errors import DynectCreateError
from dyn.tm.errors import DynectDeleteError

DYN_CUSTOMER = 'test-customer'
DYN_USERNAME = 'test-username'
DYN_PASSWORD = 'test-password'

class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common.BaseAuthenticatorTest):
    # pylint: disable=protected-access

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'dyn-test.ini')
        dns_test_common.write({
                                "dyn_customer": DYN_CUSTOMER,
                                "dyn_username": DYN_USERNAME,
                                "dyn_password": DYN_PASSWORD
                              }, path)

        self.config = mock.MagicMock(dyn_credentials=path,
                                     dyn_propagation_seconds=0)
        self.auth = Authenticator(self.config, "dyn")
        self.auth._setup_credentials()

    def test_rrem(self):
        assert rrem('a.b.c', '.c') == 'a.b'
        assert rrem('a.b.c', '.d') == 'a.b.c'

    @mock.patch('certbot_dns_dyn.dns_dyn.DynectSession')
    def test_get_dyn_client(self, patch_DynectSession):
        self.auth._get_dyn_client()
        patch_DynectSession.assert_called_once_with(DYN_CUSTOMER,
                                                    DYN_USERNAME,
                                                    DYN_PASSWORD)

    @mock.patch('certbot_dns_dyn.dns_dyn.get_all_zones')
    def test_find_zone_missing(self, patch_get_all_zones):
        patch_get_all_zones.return_value = []
        assert self.auth._find_zone('_acme-challenge.letsencrypt.org') == None
        patch_get_all_zones.assert_called_once_with()

    @mock.patch('certbot_dns_dyn.dns_dyn.get_all_zones')
    def test_find_zone(self, patch_get_all_zones):
        mock_zone = mock.Mock()
        mock_zone.fqdn = 'letsencrypt.org.'

        patch_get_all_zones.return_value = [mock_zone]
        assert self.auth._find_zone('_acme-challenge.letsencrypt.org') == mock_zone
        patch_get_all_zones.assert_called_once_with()

    @mock.patch('certbot_dns_dyn.dns_dyn.Authenticator._get_dyn_client')
    def test_perform_empty(self, patch_get_dyn_client):
        client = patch_get_dyn_client.return_value
        client.authenticate.return_value = None

        self.auth.perform([])

        patch_get_dyn_client.assert_called_once_with()
        client.authenticate.assert_called_once_with()

    @mock.patch('certbot_dns_dyn.dns_dyn.Authenticator._get_dyn_client')
    @mock.patch('certbot_dns_dyn.dns_dyn.Authenticator._find_zone')
    def test_perform_no_domain(self, patch_find_zone, patch_get_dyn_client):
        client = patch_get_dyn_client.return_value
        client.authenticate.return_value = None

        patch_find_zone.return_value = None

        with self.assertRaises(errors.PluginError):
            self.auth.perform([self.achall])

        patch_get_dyn_client.assert_called_once_with()
        client.authenticate.assert_called_once_with()

    @mock.patch('certbot_dns_dyn.dns_dyn.Authenticator._get_dyn_client')
    def test_perform_invalid_credentials(self, patch_get_dyn_client):
        client = patch_get_dyn_client.return_value
        client.authenticate = mock.Mock(side_effect=DynectAuthError(''))

        with self.assertRaises(errors.PluginError):
            self.auth.perform([self.achall])

        client.authenticate.assert_called_once_with()

    @mock.patch('certbot_dns_dyn.dns_dyn.Authenticator._get_dyn_client')
    @mock.patch('certbot_dns_dyn.dns_dyn.Authenticator._find_zone')
    def test_perform(self, patch_find_zone, patch_get_dyn_client):
        client = patch_get_dyn_client.return_value
        client.authenticate.return_value = None

        zone = patch_find_zone.return_value
        zone.fqdn = self.achall.domain
        zone.add_record = mock.Mock()
        zone.publish = mock.Mock()

        self.auth.perform([self.achall])

        expected_name = self.achall.validation_domain_name(self.achall.domain)
        expected_name = rrem(expected_name, zone.fqdn)
        expected_name = rrem(expected_name, '.')

        patch_get_dyn_client.assert_called_once_with()
        client.authenticate.assert_called_once_with()
        patch_find_zone.assert_called_once_with(self.achall.domain)
        zone.add_record.assert_called_once_with(
            expected_name,
            record_type='TXT',
            txtdata=self.achall.validation(self.achall.account_key))
        zone.publish.assert_called_once_with('Added Certbot Validation')

    @mock.patch('certbot_dns_dyn.dns_dyn.Authenticator._get_dyn_client')
    @mock.patch('certbot_dns_dyn.dns_dyn.Authenticator._find_zone')
    def test_perform_add_error(self, patch_find_zone, patch_get_dyn_client):
        client = patch_get_dyn_client.return_value
        client.authenticate.return_value = None

        zone = patch_find_zone.return_value
        zone.fqdn = self.achall.domain
        zone.add_record = mock.Mock(side_effect=DynectCreateError(''))

        with self.assertRaises(errors.PluginError):
            self.auth.perform([self.achall])

        expected_name = self.achall.validation_domain_name(self.achall.domain)
        expected_name = rrem(expected_name, zone.fqdn)
        expected_name = rrem(expected_name, '.')

        patch_get_dyn_client.assert_called_once_with()
        client.authenticate.assert_called_once_with()
        patch_find_zone.assert_called_once_with(self.achall.domain)
        zone.add_record.assert_called_once_with(
            expected_name,
            record_type='TXT',
            txtdata=self.achall.validation(self.achall.account_key))

    def test_cleanup(self):
        record = mock.Mock()
        record.fqdn = self.achall.validation_domain_name(self.achall.domain)
        record.delete = mock.Mock()

        node = mock.Mock()
        node.get_all_records_by_type = mock.Mock()
        node.get_all_records_by_type.return_value = [record]

        zone = mock.Mock()
        zone.fqdn = self.achall.domain
        zone.get_node = mock.Mock()
        zone.get_node.return_value = node

        self.auth._attempt_cleanup = True
        self.auth._zone_cache = {}
        self.auth._zone_cache[self.achall.domain] = zone
        self.auth._client = mock.Mock()
        self.auth._client.log_out = mock.Mock()

        self.auth.cleanup([self.achall])

        expected_name = record.fqdn
        expected_name = rrem(expected_name, zone.fqdn)
        expected_name = rrem(expected_name, '.')

        zone.get_node.assert_called_once_with(expected_name)
        node.get_all_records_by_type.assert_called_once_with('TXT')
        record.delete.assert_called_once_with()
        zone.publish.assert_called_once_with('Removed Certbot Validation')
        self.auth._client.log_out.assert_called_once_with()

    def test_cleanup_delete_error(self):
        record = mock.Mock()
        record.fqdn = self.achall.validation_domain_name(self.achall.domain)
        record.delete = mock.Mock(side_effect=DynectDeleteError(''))

        node = mock.Mock()
        node.get_all_records_by_type = mock.Mock()
        node.get_all_records_by_type.return_value = [record]

        zone = mock.Mock()
        zone.fqdn = self.achall.domain
        zone.get_node = mock.Mock()
        zone.get_node.return_value = node

        self.auth._attempt_cleanup = True
        self.auth._zone_cache = {}
        self.auth._zone_cache[self.achall.domain] = zone
        self.auth._client = mock.Mock()
        self.auth._client.log_out = mock.Mock()

        self.auth.cleanup([self.achall])

        expected_name = record.fqdn
        expected_name = rrem(expected_name, zone.fqdn)
        expected_name = rrem(expected_name, '.')

        zone.get_node.assert_called_once_with(expected_name)
        node.get_all_records_by_type.assert_called_once_with('TXT')
        record.delete.assert_called_once_with()
        zone.publish.assert_called_once_with('Removed Certbot Validation')
        self.auth._client.log_out.assert_called_once_with()

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
