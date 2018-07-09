"""Tests for certbot_dns_azure.dns_azure."""

import os
import unittest

import mock
from requests.exceptions import HTTPError

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

ACCOUNT_JSON_PATH = '/not/a/real/path.json'
RESOURCE_GROUP = 'test-test-1'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_azure.dns_azure import Authenticator


        self.config = mock.MagicMock(azure_credentials=ACCOUNT_JSON_PATH,
                                     azure_resource_group=RESOURCE_GROUP,
                                     dnsmadeeasy_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "azure")

        self.mock_client = mock.MagicMock()
        self.auth._get_azure_client = mock.MagicMock(return_value=self.mock_client)


class AzureClientTest(unittest.TestCase):

    def setUp(self):
        from certbot_dns_azure.dns_azure import _AzureClient

        self.client = _AzureClient(RESOURCE_GROUP, ACCOUNT_JSON_PATH)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover

