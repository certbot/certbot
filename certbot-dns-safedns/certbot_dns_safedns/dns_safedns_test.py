"""Tests for certbot_dns_safedns.dns_safedns."""

import unittest

import mock
from requests.exceptions import HTTPError, RequestException

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

DOMAIN_NOT_FOUND = Exception('No domain found')
GENERIC_ERROR = RequestException
LOGIN_ERROR = HTTPError('400 Client Error: ...')

AUTH_TOKEN = 'foo'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_safedns.dns_safedns import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"safedns_auth_token": AUTH_TOKEN}, path)

        self.config = mock.MagicMock(safedns_credentials=path,
                                     safedns_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "safedns")

        self.mock_client = mock.MagicMock()
        # _get_safedns_client | pylint: disable=protected-access
        self.auth._get_safedns_client = mock.MagicMock(return_value=self.mock_client)


class SafeDNSLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    def setUp(self):
        from certbot_dns_safedns.dns_safedns import _SafeDNSLexiconClient

        self.client = _SafeDNSLexiconClient(AUTH_TOKEN, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
