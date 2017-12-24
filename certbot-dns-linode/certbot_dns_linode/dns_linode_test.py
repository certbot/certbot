"""Tests for certbot_dns_linode.dns_linode."""

import os
import unittest

import mock

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

TOKEN = 'a-token'

class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_linode.dns_linode import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"linode_key": TOKEN}, path)

        self.configure(Authenticator(self.config, "linode"), {"credentials": path})

        self.mock_client = mock.MagicMock()
        # _get_linode_client | pylint: disable=protected-access
        self.auth._get_linode_client = mock.MagicMock(return_value=self.mock_client)

class LinodeLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    DOMAIN_NOT_FOUND = Exception('Domain not found')

    def setUp(self):
        from certbot_dns_linode.dns_linode import _LinodeLexiconClient

        self.client = _LinodeLexiconClient(TOKEN)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
