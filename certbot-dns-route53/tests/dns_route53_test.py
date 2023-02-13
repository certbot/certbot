"""Tests for certbot_dns_route53._internal.dns_route53.Authenticator"""

import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError
import pytest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN


class AuthenticatorTest(unittest.TestCase, dns_test_common.BaseAuthenticatorTest):
    # pylint: disable=protected-access

    def setUp(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        super().setUp()

        self.config = mock.MagicMock()

        # Set up dummy credentials for testing
        os.environ["AWS_ACCESS_KEY_ID"] = "dummy_access_key"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "dummy_secret_access_key"

        self.auth = Authenticator(self.config, "route53")

    def tearDown(self):
        # Remove the dummy credentials from env vars
        del os.environ["AWS_ACCESS_KEY_ID"]
        del os.environ["AWS_SECRET_ACCESS_KEY"]

    def test_perform(self):
        self.auth._change_txt_record = mock.MagicMock()
        self.auth._wait_for_change = mock.MagicMock()

        self.auth.perform([self.achall])

        self.auth._change_txt_record.assert_called_once_with("UPSERT",
                                                             '_acme-challenge.' + DOMAIN,
                                                             mock.ANY)
        self.assertEqual(self.auth._wait_for_change.call_count, 1)

    def test_perform_no_credentials_error(self):
        self.auth._change_txt_record = mock.MagicMock(side_effect=NoCredentialsError)

        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    def test_perform_client_error(self):
        self.auth._change_txt_record = mock.MagicMock(
            side_effect=ClientError({"Error": {"Code": "foo"}}, "bar"))

        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    def test_cleanup(self):
        self.auth._attempt_cleanup = True

        self.auth._change_txt_record = mock.MagicMock()

        self.auth.cleanup([self.achall])

        self.auth._change_txt_record.assert_called_once_with("DELETE",
                                                             '_acme-challenge.'+DOMAIN,
                                                             mock.ANY)

    def test_cleanup_no_credentials_error(self):
        self.auth._attempt_cleanup = True

        self.auth._change_txt_record = mock.MagicMock(side_effect=NoCredentialsError)

        self.auth.cleanup([self.achall])

    def test_cleanup_client_error(self):
        self.auth._attempt_cleanup = True

        self.auth._change_txt_record = mock.MagicMock(
            side_effect=ClientError({"Error": {"Code": "foo"}}, "bar"))

        self.auth.cleanup([self.achall])


class ClientTest(unittest.TestCase):
    # pylint: disable=protected-access

    PRIVATE_ZONE = {
                        "Id": "BAD-PRIVATE",
                        "Name": "example.com",
                        "Config": {
                            "PrivateZone": True
                        }
                    }

    EXAMPLE_NET_ZONE = {
                            "Id": "BAD-WRONG-TLD",
                            "Name": "example.net",
                            "Config": {
                                "PrivateZone": False
                            }
                        }

    EXAMPLE_COM_ZONE = {
                            "Id": "EXAMPLE",
                            "Name": "example.com",
                            "Config": {
                                "PrivateZone": False
                            }
                        }

    FOO_EXAMPLE_COM_ZONE = {
                                "Id": "FOO",
                                "Name": "foo.example.com",
                                "Config": {
                                    "PrivateZone": False
                                }
                            }

    def setUp(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        self.config = mock.MagicMock()

        # Set up dummy credentials for testing
        os.environ["AWS_ACCESS_KEY_ID"] = "dummy_access_key"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "dummy_secret_access_key"

        self.client = Authenticator(self.config, "route53")

    def tearDown(self):
        # Remove the dummy credentials from env vars
        del os.environ["AWS_ACCESS_KEY_ID"]
        del os.environ["AWS_SECRET_ACCESS_KEY"]

    def test_find_zone_id_for_domain(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.EXAMPLE_NET_ZONE,
                    self.EXAMPLE_COM_ZONE,
                ]
            }
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        self.assertEqual(result, "EXAMPLE")

    def test_find_zone_id_for_domain_pagination(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.EXAMPLE_COM_ZONE,
                ]
            },
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.FOO_EXAMPLE_COM_ZONE,
                ]
            }
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        self.assertEqual(result, "FOO")

    def test_find_zone_id_for_domain_no_results(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = []

        self.assertRaises(errors.PluginError,
                          self.client._find_zone_id_for_domain,
                          "foo.example.com")

    def test_find_zone_id_for_domain_no_correct_results(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.EXAMPLE_NET_ZONE,
                ]
            },
        ]

        self.assertRaises(errors.PluginError,
                          self.client._find_zone_id_for_domain,
                          "foo.example.com")

    def test_change_txt_record(self):
        self.client._find_zone_id_for_domain = mock.MagicMock()
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        self.client._change_txt_record("FOO", DOMAIN, "foo")

        call_count = self.client.r53.change_resource_record_sets.call_count
        self.assertEqual(call_count, 1)

    def test_change_txt_record_delete(self):
        self.client._find_zone_id_for_domain = mock.MagicMock()
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        validation = "some-value"
        validation_record = {"Value": '"{0}"'.format(validation)}
        self.client._resource_records[DOMAIN] = [validation_record]

        self.client._change_txt_record("DELETE", DOMAIN, validation)

        call_count = self.client.r53.change_resource_record_sets.call_count
        self.assertEqual(call_count, 1)
        call_args = self.client.r53.change_resource_record_sets.call_args_list[0][1]
        call_args_batch = call_args["ChangeBatch"]["Changes"][0]
        self.assertEqual(call_args_batch["Action"], "DELETE")
        self.assertEqual(
            call_args_batch["ResourceRecordSet"]["ResourceRecords"],
            [validation_record])

    def test_change_txt_record_multirecord(self):
        self.client._find_zone_id_for_domain = mock.MagicMock()
        self.client._get_validation_rrset = mock.MagicMock()
        self.client._resource_records[DOMAIN] = [
            {"Value": "\"pre-existing-value\""},
            {"Value": "\"pre-existing-value-two\""},
        ]
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        self.client._change_txt_record("DELETE", DOMAIN, "pre-existing-value")

        call_count = self.client.r53.change_resource_record_sets.call_count
        call_args = self.client.r53.change_resource_record_sets.call_args_list[0][1]
        call_args_batch = call_args["ChangeBatch"]["Changes"][0]
        self.assertEqual(call_args_batch["Action"], "UPSERT")
        self.assertEqual(
            call_args_batch["ResourceRecordSet"]["ResourceRecords"],
            [{"Value": "\"pre-existing-value-two\""}])

        self.assertEqual(call_count, 1)

    def test_wait_for_change(self):
        self.client.r53.get_change = mock.MagicMock(
            side_effect=[{"ChangeInfo": {"Status": "PENDING"}},
                         {"ChangeInfo": {"Status": "INSYNC"}}])

        self.client._wait_for_change(1)

        self.assertTrue(self.client.r53.get_change.called)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
