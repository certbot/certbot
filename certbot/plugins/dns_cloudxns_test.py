"""Tests for certbot.plugins.dns_cloudxns."""

import mock
import unittest

from requests.exceptions import HTTPError, RequestException

from certbot.plugins import dns_test_common

DOMAIN_NOT_FOUND = Exception('No domain found')
GENERIC_ERROR = RequestException
LOGIN_ERROR = HTTPError('400 Client Error: ...')

API_KEY = 'foo'
SECRET_KEY = 'bar'


class AuthenticatorTest(unittest.TestCase, dns_test_common.BaseLexiconAuthenticatorTest):

    def setUp(self):
        from certbot.plugins.dns_cloudxns import Authenticator
        self.config = mock.MagicMock(cloudxns_api_key=API_KEY,
                                     cloudxns_secret_key=SECRET_KEY,
                                     cloudxns_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "cloudxns")

        self.mock_client = mock.MagicMock()
        # _get_cloudxns_client | pylint: disable=protected-access
        self.auth._get_cloudxns_client = mock.MagicMock(return_value=self.mock_client)


class CloudXNSLexiconClientTest(unittest.TestCase, dns_test_common.BaseLexiconClientTest):

    def setUp(self):
        from certbot.plugins.dns_cloudxns import _CloudXNSLexiconClient

        self.client = _CloudXNSLexiconClient(API_KEY, SECRET_KEY, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
