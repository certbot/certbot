"""Tests for certbot_dns_linode.dns_linode."""

import os
import unittest

import mock

from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

TOKEN = 'a-token'

class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_linode.dns_linode import Authenticator

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"linode_key": TOKEN}, path)

        self.config = mock.MagicMock(linode_credentials=path,
                                     linode_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "linode")

        self.mock_client = mock.MagicMock()
        # _get_linode_client | pylint: disable=protected-access
        self.auth._get_linode_client = mock.MagicMock(return_value=self.mock_client)

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

class LinodeClientTest(unittest.TestCase):
    id = 1
    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"

    def setUp(self):
        from certbot_dns_linode.dns_linode import _LinodeClient

        self.linode_client = _LinodeClient(TOKEN)

        self.linode_api = mock.MagicMock()
        self.linode_client.linode_api = self.linode_api

    def test_add_txt_record(self):
        self.linode_api.domain_list.return_value = [
            {
                "DOMAIN": "other.invalid",
                "DOMAINID": 10000
            },
            {
                "DOMAIN": DOMAIN,
                "DOMAINID": 10001
            }
        ]

        self.linode_api.domain_resource_create.return_value = {"ResourceID": 11000}
        self.linode_client.add_txt_record(DOMAIN, self.record_name, self.record_content)
        self.linode_api.domain_resource_create.assert_called_with(DomainID=10001,
                                                                Type='TXT',
                                                                Name=self.record_prefix,
                                                                Target=self.record_content)

    def test_del_txt_record(self):
        self.linode_api.domain_list.return_value = [
            {
                "DOMAIN": DOMAIN,
                "DOMAINID": 10001
            }
        ]
        self.linode_api.domain_resource_list.return_value = [
            {
                "RESOURCEID": 11000,
                "TYPE": "TXT",
                "NAME": "DIFFERENT",
                "TARGET": self.record_content
            },
            {
                "RESOURCEID": 11001,
                "TYPE": "TXT",
                "NAME": self.record_prefix,
                "TARGET": self.record_content
            },
            {
                "RESOURCEID": 11002,
                "TYPE": "TXT",
                "NAME": self.record_prefix,
                "TARGET": "DIFFERENT"
            }
        ]

        self.linode_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.linode_api.domain_resource_delete.assert_called_with(DomainID=10001,
                                                                ResourceID=11001)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
