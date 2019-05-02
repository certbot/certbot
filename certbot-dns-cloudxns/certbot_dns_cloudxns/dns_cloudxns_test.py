"""Tests for certbot_dns_cloudxns.dns_cloudxns."""

import unittest

import mock

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

API_KEY = 'foo'
SECRET = 'bar'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_cloudxns.dns_cloudxns import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"cloudxns_api_key": API_KEY, "cloudxns_secret_key": SECRET}, path)

        self.configure(Authenticator(self.config, "cloudxns"), {"credentials": path})

        self.mock_client = mock.MagicMock()
        # _get_cloudxns_client | pylint: disable=protected-access
        self.auth._get_cloudxns_client = mock.MagicMock(return_value=self.mock_client)


class CloudXNSLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    def setUp(self):
        from certbot_dns_cloudxns.dns_cloudxns import _CloudXNSLexiconClient

        self.client = _CloudXNSLexiconClient(API_KEY, SECRET, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
